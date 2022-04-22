package vpn

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	UDPBufferSize = 8192
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
	}
}

// Client implements the OpenVPN protocol. If you're just interested in writing
// to and reading from the tunnel you should use the dialer methods instead.
// This type is only intended to be instantiated by users that need a finer control
// of the protocol steps (i.e., you want to be sure that you are only calling
// the handshake, etc.)
type Client struct {
	Opts             *Options
	HandshakeTimeout int
	localKeySrc      *keySource
	remoteKeySrc     *keySource
	ctx              context.Context
	cancel           context.CancelFunc
	initSt           int
	tunnelIP         string
	tunMTU           int
	con              net.Conn
	ctrl             *control
	data             *data
}

// Run starts the OpenVPN tunnel. It calls all the protocol steps serially.
// If you want to perform only some parts, you should use each of the methods
// above instead.
func (c *Client) Run() error {
	if err := c.Init(); err != nil {
		return err
	}
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

// Init is the first step to stablish an OpenVPN tunnel (out of five). It only
// initializes local state, so it's not expected to fail.
func (c *Client) Init() error {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	c.ctx = ctx
	c.cancel = cancel
	ks, err := newKeySource()
	c.localKeySrc = ks
	return err
}

// Dial opens a TCP/UDP socket against the remote, and creates an internal
// data channel. It is the second step in an OpenVPN connection (out of five).
// (In UDP mode no network connection is done at this step).
func (c *Client) Dial() error {
	proto := "udp"
	if c.Opts.Proto == TCPMode {
		proto = "tcp"
	}
	log.Printf("Connecting to %s:%s with proto %s\n", c.Opts.Remote, c.Opts.Port, strings.ToUpper(proto))
	// TODO pass context?
	conn, err := net.Dial(proto, net.JoinHostPort(c.Opts.Remote, c.Opts.Port))
	if err != nil {
		return fmt.Errorf("%s: %w", ErrDialError, err)
	}
	c.con = conn
	c.ctrl = newControl(conn, c.localKeySrc, c.Opts)
	c.ctrl.initSession()
	c.data = newData(c.localKeySrc, c.remoteKeySrc, c.Opts)
	c.ctrl.addDataQueue(c.data.queue)
	return nil
}

// Reset sends a hard-reset packet to the server, and waits for the server
// confirmation. It is the third step in an OpenVPN connection (out of five).
func (c *Client) Reset() error {
	log.Printf("Setting timeout to %ds.\n", c.HandshakeTimeout)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(c.HandshakeTimeout))
	defer cancel()

	c.ctrl.sendHardReset(ctx)
	r, err := c.recv(ctx, 0)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrBadHandshake, err)
	}

	id, err := c.ctrl.readHardReset(ctx, r)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrBadHandshake, err)
	}
	// this id is always going to be 0, is the first packet we ack
	log.Println("DEBUG: send ack")
	err = c.sendAck(uint32(id))
	if err != nil {
		return fmt.Errorf("%s: %w", ErrBadHandshake, err)
	}
	// TODO pass ctx, but watchout for cancel
	go c.handleIncoming()
	return nil
}

// InitTLS performs a TLS handshake over the control channel. It is the fourth
// step in an OpenVPN connection (out of five).
func (c *Client) InitTLS() error {
	err := c.ctrl.initTLS()
	c.initSt = stControlChannelOpen
	// TODO these errors can be configuration errors (loading the keypair)
	// or actual handshake errors, need to separate them.
	// perhaps it make sense to load the certificates etc before touching the net...
	return err
}

// InitData initializes the internal data channel. To do that, it sends a
// control packet, parses the response, and derives the cryptographic material
// that will be used to encrypt and decrypt data through the tunnel. At the end
// of this exchange, the data channel is ready to be used. This is the fifth
// and last step in an OpenVPN connection.
func (c *Client) InitData() error {
	for {
		select {
		case <-c.ctx.Done():
			return nil
		default:
			switch {
			case c.initSt == stControlChannelOpen:
				c.sendFirstControl()
			case c.initSt == stKeyExchanged:
				c.sendPushRequest()
			case c.initSt == stOptionsPushed:
				c.initDataChannel()
			case c.initSt == stInitialized:
				c.handleDataChannel()
				goto done
			}
		}
	}
done:
	return nil
}

func (c *Client) sendFirstControl() {
	log.Println("Control channel open, sending auth...")
	c.ctrl.sendControlMessage()
	c.initSt = stControlMessageSent
	c.handleTLSIncoming()
}

func (c *Client) sendPushRequest() {
	log.Println("Key exchange complete")
	c.ctrl.sendPushRequest()
	c.initSt = stPullRequestSent
	c.handleTLSIncoming()
}

func (c *Client) initDataChannel() {
	c.data.initSession(c.ctrl)
	c.data.setup()
	log.Println("Initialization complete")
	c.initSt = stInitialized
}

func (c *Client) handleDataChannel() {
	go c.handleTLSIncoming()
	c.initSt = stDataReady
}

func (c *Client) onKeyExchanged() {
	c.initSt = stKeyExchanged
}

func (c *Client) sendAck(ackPid uint32) error {
	// log.Printf("Client: ACK'ing packet %08x...", ackPid)
	if len(c.ctrl.RemoteID) == 0 {
		log.Println("Error: ack id cannot be zero")
		return fmt.Errorf(ErrBadInit)
	}
	p := make([]byte, 1)
	p[0] = 0x28 // P_ACK_V1 0x05 (5b) + 0x0 (3b)
	p = append(p, c.ctrl.SessionID...)
	p = append(p, 0x01)
	ack := make([]byte, 4)
	binary.BigEndian.PutUint32(ack, ackPid)
	p = append(p, ack...)
	p = append(p, c.ctrl.RemoteID...)
	if c.Opts.Proto == TCPMode {
		p = toSizeFrame(p)
	}
	c.con.Write(p)
	return nil
}

func (c *Client) handleIncoming() {
	data, err := c.recv(context.Background(), 4096)
	if err != nil {
		log.Println("DEBUG: handleIncoming error:", err.Error())
		return
	}
	if len(data) == 0 {
		return
	}

	op := data[0] >> 3
	if op == byte(pACKV1) {
		log.Println("DEBUG Received ACK in main loop")
	}
	if isControlOpcode(op) {
		c.ctrl.queue <- data
	} else if isDataOpcode(op) {
		c.data.queue <- data
	} else {
		log.Println("unhandled data:")
		log.Println(hex.EncodeToString(data))
	}
}

func (c *Client) onRemoteOpts() {
	opts := strings.Split(c.ctrl.remoteOpts, ",")
	for _, opt := range opts {
		vals := strings.Split(opt, " ")
		k, v := vals[0], vals[1:]
		if k == "tun-mtu" {
			mtu, err := strconv.Atoi(v[0])
			if err != nil {
				log.Println("bad mtu:", err)
				continue
			}
			c.tunMTU = mtu
		}
	}
}

// I don't think I want to do much with the pushed options for now, other
// than extracting the tunnel ip, but it can be useful to parse them into a map
// and compare if there's a strong disagreement with the remote opts
func (c *Client) onPush(data []byte) {
	log.Println("Server pushed options")
	c.initSt = stOptionsPushed
	optStr := string(data[:len(data)-1])
	opts := strings.Split(optStr, ",")
	for _, opt := range opts {
		vals := strings.Split(opt, " ")
		k, v := vals[0], vals[1:]
		if k == "ifconfig" {
			c.tunnelIP = v[0]
			log.Println("tunnel_ip: ", c.tunnelIP)
		}
	}
}

// TunnelIP returns the local IP that the server assigned us.
func (c *Client) TunnelIP() string {
	return c.tunnelIP
}

// TunMTU returns the tun-mtu value that the remote advertises.
func (c *Client) TunMTU() int {
	return c.tunMTU
}

func (c *Client) handleTLSIncoming() {
	var recv = make([]byte, 4096)
	var n, _ = c.ctrl.tls.Read(recv)
	data := recv[:n]
	if areBytesEqual(data[:4], []byte{0x00, 0x00, 0x00, 0x00}) {
		remoteKey := c.ctrl.readControlMessage(data)
		c.onRemoteOpts()
		// XXX update only one pointer
		c.remoteKeySrc = remoteKey
		c.data.remoteKeySource = remoteKey
		c.onKeyExchanged()
	} else {
		rpl := []byte("PUSH_REPLY")
		if areBytesEqual(data[:len(rpl)], rpl) {
			c.onPush(data)
			return
		}
		badauth := []byte("AUTH_FAILED")
		if areBytesEqual(data[:len(badauth)], badauth) {
			log.Println(string(data))
			log.Fatal("Aborting")
			return
		}
		log.Println("I DONT KNOW THAT TO DO WITH THIS")
	}
}

// Write sends bytes into the tunnel.
func (c *Client) Write(b []byte) {
	c.data.send(b)
}

// WaitUntil accepts a chan bool, and will stop the tunnel upon receiving on
// this channel.
func (c *Client) WaitUntil(done chan bool) {
	go func() {
		select {
		case <-done:
			c.Stop()
		}
	}()
}

// Stop closes the tunnel connection.
func (c *Client) Stop() {
	c.cancel()
}

func (c *Client) recv(ctx context.Context, size int) ([]byte, error) {
	if !isTCP(c.Opts.Proto) {
		if size == 0 {
			size = UDPBufferSize
		}
	}
	var recvData = make([]byte, size)
	for {
		select {
		case <-ctx.Done():
			log.Println("Timeout")
			return recvData, fmt.Errorf("timeout")
		default:
			if c.HandshakeTimeout != 0 {
				c.con.SetReadDeadline(time.Now().Add(time.Duration(c.HandshakeTimeout) * time.Second))
			}
			if isTCP(c.Opts.Proto) {
				bl := make([]byte, 2)
				_, err := c.con.Read(bl)
				if err != nil {
					log.Println("ERROR:", err)
				}
				l := int(binary.BigEndian.Uint16(bl))
				rcv := make([]byte, l)
				n, _ := c.con.Read(rcv)
				return rcv[:n], nil
			} else {
				n, err := c.con.Read(recvData)
				if err != nil {
					log.Println("DEBUG: reading data:", err)
				}
				return recvData[:n], nil
			}
		}
	}
}

// DataChannel returns the internal data channel.
// There's probably no need to export this.
func (c *Client) DataChannel() chan []byte {
	return c.data.dataChan()
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
