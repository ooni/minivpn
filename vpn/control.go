package vpn

//
// OpenVPN control channel
//

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
)

var (
	errBadReset = errors.New("bad reset packet")
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
	if p == nil {
		return false
	}
	return p.id-lastAck == 1
}

type control struct {
	// local state
	Opts    *Options
	session *session

	// TODO when is this populated?
	remoteOpts string

	tls  net.Conn
	conn net.Conn
}

var errDataChannelKey = errors.New("bad key")

// TODO pass these keys to datachannel via a key chan ??
// TODO rename: dataChannelKey
type dataChannelKey struct {
	index  uint32
	ready  bool
	local  *keySource
	remote *keySource
	mu     sync.Mutex
}

func (dck *dataChannelKey) addRemoteKey(k *keySource) error {
	dck.mu.Lock()
	defer dck.mu.Unlock()
	if dck.ready {
		return fmt.Errorf("%w:%s", errDataChannelKey, "cannot overwrite remote key slot")
	}
	dck.remote = k
	dck.ready = true
	return nil
}

type session struct {
	RemoteSessionID sessionID
	LocalSessionID  sessionID
	keys            []*dataChannelKey
	keyID           int
	localPacketID   uint32

	mu sync.Mutex
	// TODO refactor: temporary workaround ----------------------------
	// to be able to send acks during the handshake (invert dependency)
	control *control
}

// ActiveKey returns the dataChannelKey that is actively being used.
func (s *session) ActiveKey() (*dataChannelKey, error) {
	if len(s.keys) < s.keyID {
		return nil, fmt.Errorf("%w: %s", errDataChannelKey, "no such key id")
	}
	dck := s.keys[s.keyID]
	return dck, nil
}

// localPacketID returns an unique Packet ID. It increments the counter.
// TODO should warn when we're approaching the key end of life.
func (s *session) LocalPacketID() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	pid := s.localPacketID
	s.localPacketID++
	return pid
}

// there needs to be an interface between session <----> packetWriter --------------------- */
func (s *session) localPacketIDAsBytes() []byte {
	pid := make([]byte, 4)
	binary.BigEndian.PutUint32(pid, s.LocalPacketID())
	return pid
}

// TODO probably not needed, can use packet.Bytes() instead ------------------------------ */

func (s *session) makeControlPayload(data []byte) ([]byte, error) {
	var out bytes.Buffer
	out.Write([]byte(s.LocalSessionID[:]))
	out.WriteByte(0x00)
	out.Write(s.localPacketIDAsBytes())
	out.Write(data)
	return out.Bytes(), nil
}

/* REFACTOR CRUFT ------------------------------------------------------------------------ */

func newControl(c net.Conn, o *Options) *control {
	key0 := &dataChannelKey{}
	ctrl := &control{
		Opts: o,
		conn: c,
		session: &session{
			keys: []*dataChannelKey{key0},
		},
	}

	// FIXME hack! passing self pointer to tls -------------------------
	ctrl.session.control = ctrl
	// -----------------------------------------------------------------
	return ctrl
}

func (c *control) initSession() error {
	randomBytes, err := genRandomBytes(8)
	if err != nil {
		return err
	}

	// in go 1.17, one could do:
	// localSession := (*sessionID)(lsid)
	var localSession sessionID
	copy(localSession[:], randomBytes[:8])

	c.session.LocalSessionID = localSession
	log.Printf("Local session ID: %x\n", localSession.Bytes())

	localKey, err := newKeySource()
	if err != nil {
		return err
	}

	k, err := c.session.ActiveKey()
	if err != nil {
		return err
	}
	k.local = localKey

	return nil
}

func (c *control) sendHardReset() {
	c.sendControl(pControlHardResetClientV2, 0, []byte(""))
}

func (c *control) readHardReset(b []byte) error {
	p, err := newServerHardReset(b)
	if err != nil {
		return err
	}
	remoteSession, err := parseServerHardReset(p)
	c.session.RemoteSessionID = remoteSession

	// here we could check if we have received a remote session id but
	// our session.remoteSessionID is != from all zeros

	log.Printf("Learned remote session ID: %x\n", remoteSession.Bytes())
	return nil
}

func (c *control) sendControlV1(data []byte) (n int, err error) {
	return c.sendControl(pControlV1, 0, data)
}

func (c *control) sendControl(opcode int, ack int, payload []byte) (n int, err error) {
	p := newPacketFromPayload(uint8(opcode), 0, payload)
	p.localSessionID = c.session.LocalSessionID
	p.id = c.session.LocalPacketID()
	out := p.Bytes()

	// move this to the transport below, care about TCP frame there. ---------
	if isTCP(c.Opts.Proto) {
		out = toSizeFrame(out)
	}
	// REFACTOR --------------------------------------------------------------
	log.Printf("control write: (%d bytes)\n", len(out))
	fmt.Println(hex.Dump(out))
	return c.conn.Write(out)
}

// sendControlMessage sends a message over the control channel packet
// (this is not a P_CONTROL, but a message over the TLS encrypted channel).
func (c *control) sendControlMessage() error {
	key, err := c.session.ActiveKey()
	if err != nil {
		return err
	}
	payload, err := encodeClientControlMessageAsBytes(key.local, c.Opts)
	if err != nil {
		return err
	}
	c.tls.Write(payload)
	return nil
}

// readControlMessage reads a control message with authentication result data.
// it returns the remote key, remote options and an error if we cannot parse
// the data.
func (c *control) readControlMessage(d []byte) (*keySource, string, error) {
	cm := newServerControlMessageFromBytes(d)
	return parseServerControlMessage(cm)
}

func (c *control) sendPushRequest() {
	c.tls.Write(encodePushRequestAsBytes())
}

// TODO return error
func (c *control) sendAck(pid uint32) {
	panicIfFalse(len(c.session.RemoteSessionID) != 0, "tried to ack with null remote")

	ackmu.Lock()
	defer ackmu.Unlock()

	p := newACKPacket(pid, c.session)
	payload := p.Bytes()

	if isTCP(c.Opts.Proto) {
		payload = toSizeFrame(payload)
	}

	c.conn.Write(payload)
	fmt.Println("write ack:", pid)
	fmt.Println(hex.Dump(payload))
	lastAck = pid
}
