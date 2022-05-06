package vpn

//
// Client initialization and public methods
//

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

var (
	handshakeTimeout    = 30
	handshakeTimeoutEnv = "HANDSHAKE_TIMEOUT"
)

// NewClientFromSettings returns a Client configured with the given Options.
func NewClientFromSettings(o *Options) *Client {
	t := handshakeTimeout
	tenv := os.Getenv(handshakeTimeoutEnv)
	if tenv != "" {
		ti, err := strconv.Atoi(tenv)
		if err == nil {
			t = ti
		} else {
			log.Println("Cannot set timeot from env:", os.Getenv(handshakeTimeoutEnv))
		}
	}
	return &Client{
		Opts:             o,
		HandshakeTimeout: t,
		tunnel:           &tunnel{},
		DialFn:           net.Dial,
	}
}

type DialFunc func(string, string) (net.Conn, error)

// Client implements the OpenVPN protocol. If you're just interested in writing
// to and reading from the tunnel you should use the dialer methods instead.
// This type is only intended to be instantiated by users that need a finer control
// of the protocol steps (i.e., you want to be sure that you are only calling
// the handshake, etc.)
type Client struct {
	Opts             *Options
	HandshakeTimeout int
	DialFn           DialFunc

	ctrl   *control
	data   *data
	tunnel *tunnel

	conn net.Conn

	ctx    context.Context
	cancel context.CancelFunc
	rmu    sync.Mutex
}

type tunnel struct {
	ip  string
	mtu int
}

// Run starts the OpenVPN tunnel. It calls all the protocol steps serially.
// If you want to perform only some parts, you should use each of the methods
// above instead.
func (c *Client) Run() error {

	if err := c.Dial(); err != nil {
		return err
	}
	if err := c.Reset(); err != nil {
		return err
	}
	if err := c.InitTLS(); err != nil {
		return err
	}
	if err := c.InitData(); err != nil {
		return err
	}
	return nil
}

// Dial opens a TCP/UDP socket against the remote, and creates an internal
// data channel. It is the second step in an OpenVPN connection (out of five).
// (In UDP mode no network connection is done at this step).
func (c *Client) Dial() error {
	proto := protoUDP.String()
	if isTCP(c.Opts.Proto) {
		proto = protoTCP.String()
	}
	log.Printf("Connecting to %s:%s with proto %s\n", c.Opts.Remote, c.Opts.Port, strings.ToUpper(proto))
	conn, err := c.DialFn(proto, net.JoinHostPort(c.Opts.Remote, c.Opts.Port))

	if err != nil {
		return fmt.Errorf("%s: %w", ErrDialError, err)
	}
	c.conn = conn

	c.ctrl = newControl(conn, c.Opts)
	c.ctrl.initSession()
	c.data = newData(c.Opts)
	return nil
}

// Reset sends a hard-reset packet to the server, and waits for the server
// confirmation. It is the third step in an OpenVPN connection (out of five).
func (c *Client) Reset() error {
	log.Printf("Setting timeout to %ds.\n", c.HandshakeTimeout)
	c.ctrl.sendHardReset()

	// TODO refactor: parse packet -----------------------------------
	// pa := parseHardReset([]byte) (uint32, error)
	r := c.readPacket()
	err := c.ctrl.readHardReset(r)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrBadHandshake, err)
	}
	// this id is (always?) 0, is the first packet we ack
	// TODO should I parse the packet id from server instead?
	c.ctrl.sendAck(uint32(0))
	return nil
}

// InitTLS performs a TLS handshake over the control channel. It is the fourth
// step in an OpenVPN connection (out of five).
func (c *Client) InitTLS() error {
	err := c.ctrl.initTLS()
	return err
}

// InitData initializes the internal data channel. To do that, it sends a
// control packet, parses the response, and derives the cryptographic material
// that will be used to encrypt and decrypt data through the tunnel. At the end
// of this exchange, the data channel is ready to be used. This is the fifth
// and last step in an OpenVPN connection.
func (c *Client) InitData() error {
	// TODO error handling
	c.sendFirstControl()
	c.sendPushRequest()
	c.initDataChannel()
	c.handleDataChannel()
	return nil
}

func (c *Client) sendFirstControl() {
	log.Println("Control channel open, sending auth...")
	err := c.ctrl.sendControlMessage()
	if err != nil {
		// return err
		log.Println("ERROR: sendFirstControl", err.Error())
	}
	c.handleControlIncoming()
}

func (c *Client) sendPushRequest() {
	log.Println("Key exchange complete")
	c.ctrl.sendPushRequest()
	c.handleControlIncoming()
}

func (c *Client) initDataChannel() error {
	c.data.initSession(c.ctrl)
	key0, err := c.ctrl.session.ActiveKey()
	if err != nil {
		return err
	}
	err = c.data.setup(key0, c.ctrl.session)
	if err != nil {
		log.Println("ERROR: initDataChannel", err.Error())
		return err
	}
	log.Println("Initialization complete")
	return nil
}

func (c *Client) handleDataChannel() {
	go c.handleIncoming()
}

// I don't think I want to do much with the pushed options for now, other
// than extracting the tunnel ip, but it can be useful to parse them into a map
// and compare if there's a strong disagreement with the remote opts
func (c *Client) onPush(data []byte) {
	log.Println("Server pushed options")
	optStr := string(data[:len(data)-1])
	opts := strings.Split(optStr, ",")
	for _, opt := range opts {
		vals := strings.Split(opt, " ")
		k, v := vals[0], vals[1:]
		if k == "ifconfig" {
			c.tunnel.ip = v[0]
			log.Println("tunnel_ip: ", c.tunnel.ip)
		}
	}
}

// this is not really needed, can read fields --------------------
// TunnelIP returns the local IP that the server assigned us.
func (c *Client) TunnelIP() string {
	return c.tunnel.ip
}

// TunMTU returns the tun-mtu value that the remote advertises.
func (c *Client) TunMTU() int {
	return c.tunnel.mtu
}

// transport

func readPacketFromTCP(conn net.Conn) ([]byte, error) {
	lenbuff := make([]byte, 2)

	if _, err := io.ReadFull(conn, lenbuff); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(lenbuff)
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// TODO(ainghazal): move to the muxer
func (c *Client) readPacket() []byte {
	if isTCP(c.Opts.Proto) {
		b, err := readPacketFromTCP(c.conn)
		if err != nil {
			log.Println("error reading", err.Error())
			return nil
		}
		return b

	} else {
		var r = make([]byte, 4096)
		n, err := c.conn.Read(r)
		if err != nil {
			log.Println("error reading", err.Error())
			return nil
		}
		data := r[:n]
		return data
	}

}

// TODO: move to options?
func (c *Client) parseRemoteOptions(remoteOpts string) {
	opts := strings.Split(remoteOpts, ",")
	for _, opt := range opts {
		vals := strings.Split(opt, " ")
		k, v := vals[0], vals[1:]
		if k == "tun-mtu" {
			mtu, err := strconv.Atoi(v[0])
			if err != nil {
				log.Println("bad mtu:", err)
				continue
			}
			c.tunnel.mtu = mtu
		}
	}
}

// XXX mostly debug for now, this is the muxer routing stuff
func (c *Client) handleIncoming() bool {
	data := c.readPacket()
	p := newPacketFromBytes(data)
	if p.isACK() {
		log.Println("Got ACK")
		return false
	}
	if p.isControl() {
		log.Println("got control packet", len(data))
		fmt.Println(hex.Dump(p.payload))
		return true
	} else if p.isData() {
		log.Println("got data packet")
		return true
	} else {
		log.Printf("ERROR: unhandled data. (op: %d)\n", p.opcode)
		fmt.Println(hex.Dump(data))
		return false
	}
}

// TODO: refactor: move to control -----------------------------------------
func (c *Client) handleControlIncoming() error {
	data := make([]byte, 4096)
	if _, err := c.ctrl.tls.Read(data); err != nil {
		log.Println("error reading:", err.Error())
		return err
	}

	if bytes.Equal(data[:4], []byte{0x00, 0x00, 0x00, 0x00}) {
		remoteKey, opts, err := c.ctrl.readControlMessage(data)
		if err != nil {
			log.Println("ERROR: cannot parse control message")
		}
		key, err := c.ctrl.session.ActiveKey()
		if err != nil {
			log.Println("ERROR: cannot get active key", err.Error())
			return err
		}
		key.addRemoteKey(remoteKey)
		c.parseRemoteOptions(opts)
	} else {
		rpl := []byte("PUSH_REPLY")
		if bytes.Equal(data[:len(rpl)], rpl) {
			c.onPush(data)
			return nil
		}
		badauth := []byte("AUTH_FAILED")
		if bytes.Equal(data[:len(badauth)], badauth) {
			log.Println(string(data))
			log.Fatal("Aborting")
			// TODO proper error
			return fmt.Errorf("bad auth")
		}
		log.Println("ERROR: cannot handle control packet")
		fmt.Println(hex.Dump(data))
	}
	return nil
}

// -----------------------------------------------------------------------------------

// Write sends bytes into the tunnel.
func (c *Client) Write(b []byte) {
	c.data.send(b)
}

// WaitUntil accepts a chan bool, and will stop the tunnel upon receiving on
// this channel.
func (c *Client) WaitUntil(done chan bool) {
	go func() {
		<-done
		c.Stop()
	}()
}

// Stop closes the tunnel connection.

func (c *Client) Stop() {
	c.conn.Close()
}
