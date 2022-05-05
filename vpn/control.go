package vpn

//
// OpenVPN control channel
//

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"
)

/* REFACTOR CRUFT ------------------------------------------------------------------------ */
// this state should go into the mux
var (
	// XXX HACK: i'm turning this into a global state so that it's easier to refactor.
	// do not use w/o mutex.
	lastAck  uint32
	ackmu    sync.Mutex
	ackQueue = make(chan *packet, 100)
)

// this needs to be moved to muxer state
func isNextPacket(p *packet) bool {
	ackmu.Lock()
	defer ackmu.Unlock()
	return p.id-lastAck == 1
}

/* REFACTOR CRUFT ------------------------------------------------------------------------ */

func newControl(c net.Conn, k *keySource, o *Options) *control {
	q := make(chan []byte)
	return &control{
		Opts:   o,
		conn:   c,
		queue:  q,
		keySrc: k,
	}
}

type control struct {
	Opts       *Options
	RemoteID   []byte
	SessionID  []byte
	localPID   uint32
	remoteOpts string
	keySrc     *keySource

	tls       net.Conn
	conn      net.Conn
	queue     chan []byte
	dataQueue chan []byte
}

func (c *control) initSession() error {
	randomBytes, err := genRandomBytes(8)
	if err != nil {
		return err
	}
	c.SessionID = randomBytes
	log.Printf("Local session ID: %x\n", string(c.SessionID))
	return nil
}

/*
func (c *control) addDataQueue(queue chan []byte) {
	c.dataQueue = queue
}
*/

func (c *control) sendHardReset() {
	// TODO move this to packet too
	c.sendControl(pControlHardResetClientV2, 0, []byte(""))
}

func (c *control) readHardReset(d []byte) (int, error) {
	if len(d) == 0 {
		return 0, nil
	}
	// TODO opcode??
	// REFACTOR: use parsed packet -------------------------------------
	if d[0] != 0x40 {
		return 0, fmt.Errorf("not a hard reset response packet")
	}

	// REFACTOR: get from session --------------------------------------
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

func (c *control) sendControlV1(data []byte) (n int, err error) {
	return c.sendControl(pControlV1, 0, data)
}

func (c *control) sendControl(opcode int, ack int, payload []byte) (n int, err error) {
	// -----------------------------------------------------
	// REFACTOR pa := newPacket() ... + serialize isn't it?
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
	log.Printf("control write: (%d bytes)\n", len(p))
	fmt.Println(hex.Dump(p))
	return c.conn.Write(p)
}

// sends a control channel packet, not a P_CONTROL
// TODO(ainghazal): return error too
func (c *control) sendControlMessage() {
	payload, err := encodeClientControlMessageAsBytes(c.keySrc, c.Opts)
	if err != nil {
		log.Println("ERROR: cannot encode control message", err.Error())
	}
	// this is the first control message *after* the handshake.
	// we send it through the *encrypted* control channel.
	// this write is now encrypted by the tls conn!
	c.tls.Write(payload)
}

// reads the control message with authentication result data
func (c *control) readControlMessage(d []byte) *keySource {
	cm := newServerControlMessageFromBytes(d)
	key, options, err := parseServerControlMessage(cm)
	if err != nil {
		log.Printf("ERROR bad control message from server: %s\n", err.Error())
	}
	c.remoteOpts = options
	return key
}

func (c *control) sendPushRequest() {
	c.tls.Write(encodePushRequestAsBytes())
}

// TODO return error
func (c *control) sendAck(pid uint32) {
	panicIfFalse(len(c.RemoteID) != 0, "tried to ack with null remote")

	ackmu.Lock()
	defer ackmu.Unlock()

	p := newACKPacket(pid, c.SessionID, c.RemoteID)
	payload := p.Bytes()

	if isTCP(c.Opts.Proto) {
		payload = toSizeFrame(payload)
	}

	c.conn.Write(payload)
	fmt.Println("write ack:", pid)
	fmt.Println(hex.Dump(payload))
	lastAck = pid
}
