package vpn

import (
	"encoding/binary"
	"log"
	"net"
	"os"
	"time"
)

func newControl(c net.Conn, k *keySource, a *Auth) *control {
	q := make(chan []byte)
	tlsIn := make(chan []byte, 10)
	return &control{
		Auth:   a,
		conn:   c,
		queue:  q,
		tlsIn:  tlsIn,
		keySrc: k,
	}
}

type control struct {
	Auth       *Auth
	RemoteID   []byte
	SessionID  []byte
	localPID   uint32
	tls        net.Conn
	conn       net.Conn
	keySrc     *keySource
	queue      chan []byte
	dataQueue  chan []byte
	tlsIn      chan []byte
	remoteOpts string
	lastAck    int
}

func (c *control) processIncoming() {
	for {
		select {
		case data := <-c.queue:
			c.handleIn(data)
		}

	}
}

func (c *control) initSession() error {
	b, err := genRandomBytes(8)
	if err != nil {
		return err
	}
	c.SessionID = b
	log.Printf("Local session ID: %x\n", string(c.SessionID))
	go c.processIncoming()
	return nil
}

// this is hacky, needs refactor. just trying to pass the data packets
// to the data queue for now.
func (c *control) addDataQueue(queue chan []byte) {
	c.dataQueue = queue
}

func (c *control) sendHardReset() {
	// log.Println("Sending HARD_RESET")
	c.sendControl(P_CONTROL_HARD_RESET_CLIENT_V2, 0, []byte(""))
}

// XXX refactor with readControl
func (c *control) readHardReset(d []byte) int {
	if d[0] != 0x40 {
		log.Fatal("Not a hard reset response packet")
	}
	if len(c.RemoteID) != 0 {
		if !areBytesEqual(c.RemoteID[:], d[1:9]) {
			log.Printf("Offending session id: %08x\n", d[1:9])
			log.Fatal("Invalid remote session ID!")
		}
	} else {
		c.RemoteID = d[1:9]
		log.Printf("Learned Remote Session id: %x\n", c.RemoteID)
	}
	return 0
}

func (c *control) sendControlV1(data []byte) (n int, err error) {
	// log.Printf("DEBUG Sending CONTROL_V1 %08x (with %d bytes)...", c.localPID, len(data))
	return c.sendControl(P_CONTROL_V1, 0, data)
}

func (c *control) sendControl(opcode int, ack int, payload []byte) (n int, err error) {
	p := make([]byte, 1)
	p[0] = byte(opcode << 3)
	p = append(p, c.SessionID...)
	p = append(p, 0x00) // no ack, so zero byte
	// FIXME if ack, append the array
	pid := make([]byte, 4)
	binary.BigEndian.PutUint32(pid, c.localPID)
	p = append(p, pid...)
	c.localPID += 1
	if len(payload) != 0 {
		p = append(p, payload...)
	}
	return c.conn.Write(p)
}

func (c *control) readControl(d []byte) (uint32, []uint32, []byte) {
	if d[0] != 0x20 {
		log.Println("OPCODE mismatch:", d[0])
	}
	if len(c.RemoteID) != 0 {
		if !areBytesEqual(c.RemoteID[:], d[1:9]) {
			log.Printf("Offending session id: %08x\n", d[1:9])
			log.Fatal("Invalid remote session ID!")
		}
	} else {
		c.RemoteID = d[1:9]
		log.Printf("Learned Remote Session id: %x\n", c.RemoteID)
	}
	ackLen := int(d[9])
	offset := 10
	ack := []uint32{}
	for i := 0; i < ackLen; i++ {
		ack = append(ack, binary.BigEndian.Uint32(d[offset:offset+4]))
		offset = offset + 4
	}
	if ackLen != 0 {
		ackSession := d[offset : offset+8]
		offset = offset + 8
		if !areBytesEqual(ackSession, c.SessionID) {
			log.Printf("Invalid local session ID in ACK: expected %08x, got %08x\n", c.SessionID, ackSession)
			log.Println("delay to shutdown...")
			time.Sleep(5 * time.Second)
			log.Fatal("Error in ACK")
		}
	}
	packetID := binary.BigEndian.Uint32(d[offset : offset+4])
	offset += 4
	payload := d[offset:]
	// log.Printf("DEBUG received P_CONTROL %08x (with %d bytes)...\n", packetID, len(payload))
	return packetID, ack, payload
}

// sends a control channel packet, not a P_CONTROL
func (c *control) sendControlMessage() {
	// TODO get user & pass from parsing auth-user-pass creds file
	user := os.Getenv("VPN_USERNAME")
	pass := ""
	if user != "" {
		pass = os.Getenv("VPN_PASSWORD")
		if len(pass) == 0 {
			log.Fatal("ERROR: Need VPN credentials to continue!")
		}
	}
	d := []byte{0x00, 0x00, 0x00, 0x00}
	d = append(d, 0x02) // key method (2)
	d = append(d, c.keySrc.Bytes()...)
	d = append(d, encodeBytes(getOptions())...)
	d = append(d, encodeBytes([]byte(user))...)
	d = append(d, encodeBytes([]byte(pass))...)
	c.tls.Write(d)
}

// reads the control message with authentication result data
func (c *control) readControlMessage(d []byte) *keySource {
	if len(d) < 71 {
		log.Println("len(data):", len(d))
		log.Fatal("Control message too short!")
	}
	if !areBytesEqual(d[:4], []byte{0x00, 0x00, 0x00, 0x00}) {
		log.Println(d[:4])
		log.Fatal("Invalid control message header")
	}
	keyMethod := d[4]
	if keyMethod != 2 {
		log.Printf("key method: %d\n", keyMethod)
		log.Fatal("Unsupported key method")
	}
	offset := 5
	random1 := d[offset : offset+32]
	offset += 32
	random2 := d[offset : offset+32]
	offset += 32
	optLen := binary.BigEndian.Uint16(d[offset:offset+2]) - 1
	remoteOpts := string(d[offset : offset+int(optLen)])

	// TODO convert this to a settings struct
	log.Println("Remote opts:", remoteOpts)
	c.remoteOpts = remoteOpts

	// log.Printf("Received Control Message: %d bytes\n", len(d))
	remoteKey := &keySource{r1: random1, r2: random2}
	return remoteKey
}

func (c *control) sendPushRequest() {
	log.Println("Sending push request")
	c.tls.Write(append([]byte("PUSH_REQUEST"), 0x00))
}

func (c *control) sendAck(pid uint32) {
	// log.Printf("Control: ACK'ing packet %08x...", pid)
	if int(pid)-c.lastAck > 1 {
		log.Println("Out of order, delay...")
		go func() {
			time.Sleep(500 * time.Millisecond)
			c.sendAck(pid)
		}()
		return
	}
	if len(c.RemoteID) == 0 {
		log.Fatal("Remote session should not be null!")
	}
	p := make([]byte, 1)
	p[0] = 0x28 // P_ACK_V1 0x05 (5b) + 0x0 (3b)
	p = append(p, c.SessionID...)
	p = append(p, 0x01)
	ack := make([]byte, 4)
	binary.BigEndian.PutUint32(ack, pid)
	p = append(p, ack...)
	p = append(p, c.RemoteID...)
	c.conn.Write(p)
	c.lastAck = int(pid)
}

func (c *control) recv() {
	var recv = make([]byte, 4096)
	var numBytes, _ = c.conn.Read(recv)
	data := recv[:numBytes]
	op := data[0] >> 3

	if op == byte(P_ACK_V1) {
		log.Println("Received ACK")
	}
}

func (c *control) handleIn(data []byte) {
	op := data[0] >> 3
	if op == byte(P_CONTROL_V1) {
		pid, _, payload := c.readControl(data)
		c.sendAck(uint32(pid))
		c.tlsIn <- payload
	}
}
