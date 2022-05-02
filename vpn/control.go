package vpn

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
)

func newControl(c net.Conn, k *keySource, o *Options) *control {
	q := make(chan []byte)
	tlsIn := make(chan []byte, 10)
	return &control{
		Opts:   o,
		conn:   c,
		queue:  q,
		tlsIn:  tlsIn,
		keySrc: k,
	}
}

type control struct {
	Opts       *Options
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
	ackmu      sync.Mutex
}

func (c *control) processIncoming() {
	for data := range c.queue {
		c.handleIn(data)
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

func (c *control) sendHardReset(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			c.sendControl(pControlHardResetClientV2, 0, []byte(""))
			return
		}
	}
}

func (c *control) readHardReset(ctx context.Context, d []byte) (int, error) {
	for {
		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("timeout")
		default:
			if len(d) == 0 {
				return 0, nil
			}
			if d[0] != 0x40 {
				return 0, fmt.Errorf("not a hard reset response packet")
			}
			if len(c.RemoteID) != 0 {
				if !bytes.Equal(c.RemoteID[:], d[1:9]) {
					log.Printf("Offending session ID: %08x\n", d[1:9])
					return 0, fmt.Errorf("invalid remote session ID")
				}
			} else {
				c.RemoteID = d[1:9]
				log.Printf("Learned remote session ID: %x\n", c.RemoteID)
			}
			return 0, nil
		}
	}
}

func (c *control) sendControlV1(data []byte) (n int, err error) {
	return c.sendControl(pControlV1, 0, data)
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
	c.localPID++
	if len(payload) != 0 {
		p = append(p, payload...)
	}
	if isTCP(c.Opts.Proto) {
		p = toSizeFrame(p)
	}
	return c.conn.Write(p)
}

func (c *control) readControl(d []byte) (uint32, []uint32, []byte) {
	if d[0] != 0x20 {
		log.Println("OPCODE mismatch:", d[0])
	}
	if len(c.RemoteID) != 0 {
		if !bytes.Equal(c.RemoteID[:], d[1:9]) {
			log.Printf("Offending session ID: %08x\n", d[1:9])
			log.Fatal("Invalid remote session ID!")
		}
	} else {
		c.RemoteID = d[1:9]
		log.Printf("Learned Remote session ID: %x\n", c.RemoteID)
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
		if !bytes.Equal(ackSession, c.SessionID) {
			log.Printf("Invalid local session ID in ACK: expected %08x, got %08x\n", c.SessionID, ackSession)
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
	d := []byte{0x00, 0x00, 0x00, 0x00}
	d = append(d, 0x02) // key method (2)
	d = append(d, c.keySrc.Bytes()...)
	d = append(d, encodeBytes(getOptionsAsBytes(c.Opts))...)
	d = append(d, encodeBytes([]byte(c.Opts.Username))...)
	d = append(d, encodeBytes([]byte(c.Opts.Password))...)
	c.tls.Write(d)
}

// reads the control message with authentication result data
func (c *control) readControlMessage(d []byte) *keySource {
	if len(d) < 71 {
		log.Println("len(data):", len(d))
		log.Fatal("Control message too short!")
	}
	if !bytes.Equal(d[:4], []byte{0x00, 0x00, 0x00, 0x00}) {
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

	log.Println("Remote opts:", remoteOpts)
	c.remoteOpts = remoteOpts

	remoteKey := &keySource{r1: random1, r2: random2}
	return remoteKey
}

func (c *control) sendPushRequest() {
	log.Println("Sending push request")
	c.tls.Write(append([]byte("PUSH_REQUEST"), 0x00))
}

func (c *control) sendAck(pid uint32) {
	c.ackmu.Lock()
	defer c.ackmu.Unlock()
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
	if isTCP(c.Opts.Proto) {
		p = toSizeFrame(p)
	}
	c.conn.Write(p)
	c.lastAck = int(pid)
}

func (c *control) handleIn(data []byte) {
	log.Println("handle in: ", len(data))

	op := data[0] >> 3
	if op == byte(pControlV1) {
		pid, _, payload := c.readControl(data)
		c.sendAck(uint32(pid))
		c.tlsIn <- payload
	}
}
