package vpn

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"log"
	"net"
	"strings"
)

type DataHandler interface {
	Run()
}

type Auth struct {
	Ca   string
	Cert string
	Key  string
	User string
	Pass string
}

func NewClientFromSettings(o *Options) *Client {
	o.Proto = "udp"
	return &Client{
		Opts: o,
	}
}

type Client struct {
	DataHandler  DataHandler
	Opts         *Options
	localKeySrc  *keySource
	remoteKeySrc *keySource
	ctx          context.Context
	cancel       context.CancelFunc
	//Done         chan bool
	initSt   int
	tunnelIP string
	con      net.Conn
	ctrl     *control
	data     *data
}

func (c *Client) Run() {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	c.ctx = ctx
	c.cancel = cancel

	c.localKeySrc = newKeySource()
	log.Printf("Connecting to %s:%s with proto UDP\n", c.Opts.Remote, c.Opts.Port)

	conn, err := net.Dial(c.Opts.Proto, net.JoinHostPort(c.Opts.Remote, c.Opts.Port))
	checkError(err)
	c.con = conn
	c.ctrl = newControl(conn, c.localKeySrc, c.Opts)
	c.ctrl.initSession()
	c.data = newData(c.localKeySrc, c.remoteKeySrc, c.Opts)
	c.ctrl.addDataQueue(c.data.queue)

	c.ctrl.sendHardReset()
	id := c.ctrl.readHardReset(c.recv(0))
	c.sendAck(uint32(id))
	go c.handleIncoming()

	c.ctrl.initTLS()
	c.initSt = ST_CONTROL_CHANNEL_OPEN

	for {
		select {
		case <-ctx.Done():
			return
		default:
			switch {
			case c.initSt == ST_CONTROL_CHANNEL_OPEN:
				c.sendFirstControl()
			case c.initSt == ST_KEY_EXCHANGED:
				c.sendPushRequest()
			case c.initSt == ST_OPTIONS_PUSHED:
				c.initDataChannel()
			case c.initSt == ST_INITIALIZED:
				c.handleDataChannel()
			}
		}
	}
}

func (c *Client) sendFirstControl() {
	log.Println("Control channel open, sending auth...")
	c.ctrl.sendControlMessage()
	c.initSt = ST_CONTROL_MESSAGE_SENT
	c.handleTLSIncoming()
}

func (c *Client) sendPushRequest() {
	log.Println("Key exchange complete")
	c.ctrl.sendPushRequest()
	c.initSt = ST_PULL_REQUEST_SENT
	c.handleTLSIncoming()
}

func (c *Client) initDataChannel() {
	c.data.initSession(c.ctrl)
	c.data.setup()
	log.Println("Initialization complete")
	c.initSt = ST_INITIALIZED
}

func (c *Client) handleDataChannel() {
	go c.handleTLSIncoming()
	go c.DataHandler.Run()
	c.initSt = ST_DATA_READY
}

func (c *Client) onKeyExchanged() {
	c.initSt = ST_KEY_EXCHANGED
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
	if op == byte(P_ACK_V1) {
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

// I don't think I want to do much with the pushed options for now, other
// than extracting the tunnel ip, but it can be useful to parse them into a map
// and compare if there's a strong disagreement with the remote opts
func (c *Client) onPush(data []byte) {
	log.Println("Server pushed options")
	c.initSt = ST_OPTIONS_PUSHED
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

func (c *Client) TunnelIP() string {
	return c.tunnelIP
}

func (c *Client) handleTLSIncoming() {
	var recv = make([]byte, 4096)
	var n, _ = c.ctrl.tls.Read(recv)
	data := recv[:n]
	if areBytesEqual(data[:4], []byte{0x00, 0x00, 0x00, 0x00}) {
		remoteKey := c.ctrl.readControlMessage(data)
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

func (c *Client) SendData(b []byte) {
	c.data.send(b)
}

func (c *Client) WaitUntil(done chan bool) {
	go func() {
		select {
		case <-done:
			c.Stop()
		}
	}()
}

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

func (c *Client) DataChannel() chan []byte {
	return c.data.dataChan()
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
