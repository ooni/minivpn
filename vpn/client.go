package vpn

import (
	"encoding/binary"
	"log"
	"net"
	"time"
)

type DataHandler interface {
	InitConsumer()
	ConsumeData()
}

type Client struct {
	Host        string
	Port        string
	Proto       string
	DataHandler DataHandler

	localKeySrc  *keySource
	remoteKeySrc *keySource
	running      bool
	initSt       int
	con          net.Conn
	ctrl         *control
	data         *data
}

func (c *Client) Run() {
	c.localKeySrc = newKeySource()
	log.Printf("Connecting to %s:%s UDP...\n", c.Host, c.Port)
	conn, err := net.Dial(c.Proto, c.Host+":"+c.Port)
	checkError(err)
	c.con = conn
	c.ctrl = newControl(conn, c.localKeySrc)
	log.Println("Control Channel created")
	c.ctrl.initSession()
	c.data = newData(c.localKeySrc, c.remoteKeySrc)
	c.ctrl.addDataQueue(c.data.queue)
	c.ctrl.sendHardReset()
	id := c.ctrl.readHardReset(c.recv(0))
	c.sendAck(uint32(id))
	go func() {
		c.handleIncoming()

	}()
	for {
		if c.ctrl.initTLS() {
			break
		}
	}
	c.running = true
	c.initSt = ST_CONTROL_CHANNEL_OPEN
	log.Println("Entering main loop")

	go func() {
		// just to debug, this should get a signal on a channel from a SIGINT etc
		time.Sleep(60 * time.Second)
		c.stop()
	}()

	for {
		if !c.running {
			break
		}
		if c.initSt == ST_CONTROL_CHANNEL_OPEN {
			log.Println("Control channel open, sending auth...")
			c.ctrl.sendControlMessage()
			c.initSt = ST_CONTROL_MESSAGE_SENT
			c.handleTLSIncoming()
		} else if c.initSt == ST_KEY_EXCHANGED {
			log.Println("Key exchange complete, pulling config...")
			c.ctrl.sendPushRequest()
			c.initSt = ST_PULL_REQUEST_SENT
			c.handleTLSIncoming()
		} else if c.initSt == ST_OPTIONS_PUSHED {
			c.data.initSession(c.ctrl)
			c.data.setup()
			log.Println(">> Initialization complete")
			c.initSt = ST_INITIALIZED
		} else if c.initSt == ST_INITIALIZED {
			go c.handleTLSIncoming()
			c.DataHandler.InitConsumer()
			c.initSt = ST_DATA_READY
		} else if c.initSt == ST_DATA_READY {
			c.handleTLSIncoming()
		}
	}
	log.Println("bye!")
}

func (c *Client) sendAck(ackPid uint32) {
	log.Printf("Client: ACK'ing packet %08x...", ackPid)
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
	}
}

func (c *Client) onKeyExchanged() {
	c.initSt = ST_KEY_EXCHANGED
}

// I don't think I want to do anything with the pushed options for now
// but it can be useful to parse them into a map, at least to know that
// we've reached this stage
func (c *Client) onPush(data []byte) {
	log.Println("==> server pushed options:")
	c.initSt = ST_OPTIONS_PUSHED
	log.Println(string(data[:len(data)-1]))
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
		}
		badauth := []byte("AUTH_FAILED")
		if areBytesEqual(data[:len(badauth)], badauth) {
			log.Fatal("Auth failed")
		}
	}
}

func (c *Client) recv(size int) []byte {
	if size == 0 {
		size = 8192
	}
	var recvData = make([]byte, size)
	var numBytes, _ = c.con.Read(recvData)
	return recvData[:numBytes]
}

func (c *Client) GetDataChannel() chan []byte {
	return c.data.getDataChan()
}

func (c *Client) stop() {
	c.running = false
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
