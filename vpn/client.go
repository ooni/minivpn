package vpn

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"log"
	"net"
	"strconv"
	"strings"
)

// NewClientFromSettings returns a Client configured with the given Options.
func NewClientFromSettings(o *Options) *Client {
	o.Proto = "udp"
	return &Client{
		Opts: o,
	}
}

// Client implements the OpenVPN protocol. If you're just interested in writing
// to and reading from the tunnel you should use the dialer methods instead.
// This type is only intended to be instantiated by users that need a finer control
// of the protocol steps (i.e., you want to be sure that you are only calling
// the handshake, etc.)
type Client struct {
	Opts         *Options
	localKeySrc  *keySource
	remoteKeySrc *keySource
	ctx          context.Context
	cancel       context.CancelFunc
	initSt       int
	tunnelIP     string
	tunMTU       int
	con          net.Conn
	ctrl         *control
	data         *data
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
	c.localKeySrc = newKeySource()
	return nil
}

// Dial opens an UDP socket against the remote, and creates an internal
// data channel. It is the second step in an OpenVPN connection (out of five).
func (c *Client) Dial() error {
	log.Printf("Connecting to %s:%s with proto UDP\n", c.Opts.Remote, c.Opts.Port)
	// TODO pass context?
	conn, err := net.Dial(c.Opts.Proto, net.JoinHostPort(c.Opts.Remote, c.Opts.Port))
	if err != nil {
		// TODO wrap this error
		return err
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
	c.ctrl.sendHardReset()
	id := c.ctrl.readHardReset(c.recv(0))
	c.sendAck(uint32(id))
	// should we block/wait until we see the response?
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

func (c *Client) sendAck(ackPid uint32) {
	// log.Printf("Client: ACK'ing packet %08x...", ackPid)
	if len(c.ctrl.RemoteID) == 0 {
		log.Fatal("Remote session should not be null!")
	}
	p := make([]byte, 1)
	p[0] = 0x28 // P_ACK_V1 0x05 (5b) + 0x0 (3b)
	p = append(p, c.ctrl.SessionID...)
	p = append(p, 0x01)
	ack := make([]byte, 4)
	binary.BigEndian.PutUint32(ack, ackPid)
	p = append(p, ack...)
	p = append(p, c.ctrl.RemoteID...)
	c.con.Write(p)
}

func (c *Client) handleIncoming() {
	data := c.recv(4096)
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

func (c *Client) recv(size int) []byte {
	if size == 0 {
		size = 8192
	}
	var recvData = make([]byte, size)
	var numBytes, _ = c.con.Read(recvData)
	return recvData[:numBytes]
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
