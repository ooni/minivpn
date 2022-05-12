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
	"math"
	"net"
	"sync"
)

var (
	errBadReset   = errors.New("bad reset packet")
	errExpiredKey = errors.New("max packet id reached")
)

var (
	serverPushReply = []byte("PUSH_REPLY")
	serverBadAuth   = []byte("AUTH_FAILED")
)

// session keeps mutable state related to an OpenVPN session.
type session struct {
	RemoteSessionID sessionID
	LocalSessionID  sessionID
	keys            []*dataChannelKey
	keyID           int
	localPacketID   packetID
	lastACK         packetID
	ackQueue        chan *packet
	mu              sync.Mutex
	Log             Logger
}

// newSession returns a session ready to be used.
func newSession() (*session, error) {
	key0 := &dataChannelKey{}
	ackQueue := make(chan *packet, 100)
	session := &session{
		keys:     []*dataChannelKey{key0},
		ackQueue: ackQueue,
	}

	randomBytes, err := genRandomBytes(8)
	if err != nil {
		return session, err
	}

	// in go 1.17, one could do:
	// localSession := (*sessionID)(lsid)
	var localSession sessionID
	copy(localSession[:], randomBytes[:8])
	session.LocalSessionID = localSession

	localKey, err := newKeySource()
	if err != nil {
		return session, err
	}

	k, err := session.ActiveKey()
	if err != nil {
		return session, err
	}
	k.local = localKey
	return session, nil
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
// In the future, this call could detect (or warn us) when we're approaching
// the key end of life.
func (s *session) LocalPacketID() (packetID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pid := s.localPacketID
	if pid == math.MaxUint32 {
		// we reached the max packetID, increment will overflow
		return 0, errExpiredKey
	}
	s.localPacketID++
	return pid, nil
}

// UpdateLastACK will update the internal variable for the last acknowledged
// packet to the passed packetID, only if packetID is greater than the lastACK.
func (s *session) UpdateLastACK(newPacketID packetID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastACK == math.MaxUint32 {
		return errExpiredKey
	}
	if s.lastACK != 0 && newPacketID <= s.lastACK {
		logger.Warnf("tried to write ack %d; last was %d", newPacketID, s.lastACK)
	}
	s.lastACK = newPacketID
	return nil
}

// isNextPacket returns true if the packetID is the next integer
// from the last acknowledged packet.
func (s *session) isNextPacket(p *packet) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p == nil {
		return false
	}
	return p.id-s.lastACK == 1
}

// control implements the controlHandler interface.
// Like true pirates, there is no state under control.
type control struct{}

func (c *control) SendHardReset(conn net.Conn, s *session) {
	sendControlPacket(conn, s, pControlHardResetClientV2, 0, []byte(""))
}

func (c *control) ParseHardReset(b []byte) (sessionID, error) {
	return parseHardReset(b)
}

func (c *control) PushRequest() []byte {
	return encodePushRequestAsBytes()
}

func (*control) ReadPushResponse(b []byte) string {
	// this is a single string containing the tunnel ip
	return parsePushedOptions(b)
}

func (c *control) ControlMessage(s *session, o *Options) ([]byte, error) {
	return encodeControlMessage(s, o)
}

func (c *control) ReadControlMessage(b []byte) (*keySource, string, error) {
	return readControlMessage(b)
}

func (c *control) SendACK(conn net.Conn, s *session, pid packetID) error {
	return sendACK(conn, s, pid)
}

var _ controlHandler = &control{} // Ensure that we implement controlHandler

// sendControlPacket crafts a control packet with the given opcode and payload,
// and writes it to the passed net.Conn.
func sendControlPacket(conn net.Conn, s *session, opcode int, ack int, payload []byte) (n int, err error) {
	p := newPacketFromPayload(uint8(opcode), 0, payload)
	p.localSessionID = s.LocalSessionID

	p.id, err = s.LocalPacketID()
	if err != nil {
		return 0, err
	}
	out := p.Bytes()

	out = maybeAddSizeFrame(conn, out)

	logger.Debug(fmt.Sprintf("control write: (%d bytes)\n", len(out)))
	logger.Debug(fmt.Sprintln(hex.Dump(out)))
	return conn.Write(out)
}

// sendACK builds an ACK control packet for the given packetID, and writes it
// over the passed connection.
func sendACK(conn net.Conn, s *session, pid packetID) error {
	panicIfFalse(len(s.RemoteSessionID) != 0, "tried to ack with null remote")

	p := newACKPacket(pid, s)
	payload := p.Bytes()
	payload = maybeAddSizeFrame(conn, payload)

	_, err := conn.Write(payload)
	if err != nil {
		return err
	}

	logger.Debug(fmt.Sprintln("write ack:", pid))
	logger.Debug(fmt.Sprintln(hex.Dump(payload)))

	s.UpdateLastACK(pid)
	return err
}

// parseHardReset extracts the sessionID from a hard-reset server response, and
// an error if the operation was not successful.
func parseHardReset(b []byte) (sessionID, error) {
	p, err := newServerHardReset(b)
	if err != nil {
		return sessionID{}, err
	}
	return parseServerHardResetPacket(p)
}

// sendControlMessage sends a message over the control channel packet
// (this is not a P_CONTROL, but a message over the TLS encrypted channel).
func encodeControlMessage(s *session, opt *Options) ([]byte, error) {
	key, err := s.ActiveKey()
	if err != nil {
		return []byte{}, err
	}
	return encodeClientControlMessageAsBytes(key.local, opt)
}

// readControlMessage reads a control message with authentication result data.
// it returns the remote key, remote options and an error if we cannot parse
// the data.
func readControlMessage(b []byte) (*keySource, string, error) {
	cm := newServerControlMessageFromBytes(b)
	return parseServerControlMessage(cm)
}

// isControlMessage returns a boolean indicating whether the header of a
// payload indicates a control message.
func isControlMessage(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	return bytes.Equal(b[:4], controlMessageHeader)
}

// maybeAddSizeFrame prepends a two-byte header containing the size of the
// payload if the network type for the passed net.Conn is not UDP (assumed to
// be TCP).
func maybeAddSizeFrame(conn net.Conn, payload []byte) []byte {
	switch conn.LocalAddr().Network() {
	case "udp", "udp4", "udp6":
		// nothing to do for UDP
		return payload
	// TODO not catching tcp explicitely because it makes it harder to test.
	// For now I rely on the client to filter out non-tcp networks.
	default:
		lenght := make([]byte, 2)
		binary.BigEndian.PutUint16(lenght, uint16(len(payload)))
		return append(lenght, payload...)
	}
}

// isBadAuthReply returns true if the passed payload is a "bad auth" server
// response; false otherwise.
func isBadAuthReply(b []byte) bool {
	l := len(serverBadAuth)
	if len(b) < l {
		return false
	}
	return bytes.Equal(b[:l], serverBadAuth)
}

// isPushReply returns true if the passed payload is a "push reply" server
// response; false otherwise.
func isPushReply(b []byte) bool {
	l := len(serverPushReply)
	if len(b) < l {
		return false
	}
	return bytes.Equal(b[:l], serverPushReply)
}
