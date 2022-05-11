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
	"net"
	"sync"
)

var (
	errBadReset = errors.New("bad reset packet")
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
	localPacketID   uint32
	lastACK         uint32
	ackQueue        chan *packet

	mu  sync.Mutex
	Log Logger
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

	logger.Info(fmt.Sprintf("Local session ID:  %x", localSession.Bytes()))

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
// TODO should warn when we're approaching the key end of life.
func (s *session) LocalPacketID() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	pid := s.localPacketID
	s.localPacketID++
	return pid
}

// UpdateLastACK will update the internal variable for the last acknowledged
// packet to the passed packetID, only if packetID is greater than the lastACK.
func (s *session) UpdateLastACK(packetID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if packetID <= s.lastACK {
		logger.Warnf("tried to write ack %d; last was %d", packetID, s.lastACK)
		return
	}
	s.lastACK = packetID
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

// control implements the controlHandler interface. Like true pirates, it has
// no state.
type control struct{}

var _ controlHandler = &control{} // Ensure that we implement controlHandler

//
// write funcs
//

/*
// TODO was this used somewhere? delete if not.
func sendControlV1(conn net.Conn, s *session, data []byte) (n int, err error) {
	return sendControlPacket(conn, s, pControlV1, 0, data)
}
*/

func (c *control) SendHardReset(conn net.Conn, s *session) {
	sendControlPacket(conn, s, pControlHardResetClientV2, 0, []byte(""))
}

func sendControlPacket(conn net.Conn, s *session, opcode int, ack int, payload []byte) (n int, err error) {
	p := newPacketFromPayload(uint8(opcode), 0, payload)
	p.localSessionID = s.LocalSessionID

	p.id = s.LocalPacketID()
	out := p.Bytes()

	out = maybeAddSizeFrame(conn, out)

	logger.Debug(fmt.Sprintf("control write: (%d bytes)\n", len(out)))
	logger.Debug(fmt.Sprintln(hex.Dump(out)))
	return conn.Write(out)
}

// sendACK builds an ACK control packet for the given packetID, and writes it
// over the passed connection.
func sendACK(conn net.Conn, s *session, pid uint32) error {
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

//
// read functions
//

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

func isControlMessage(b []byte) bool {
	return bytes.Equal(b[:4], controlMessageHeader)
}

// readControlMessage reads a control message with authentication result data.
// it returns the remote key, remote options and an error if we cannot parse
// the data.

func readControlMessage(d []byte) (*keySource, string, error) {
	cm := newServerControlMessageFromBytes(d)
	return parseServerControlMessage(cm)
}

func maybeAddSizeFrame(conn net.Conn, payload []byte) []byte {
	switch conn.LocalAddr().Network() {
	case "tcp", "tcp4", "tcp6":
		lenght := make([]byte, 2)
		binary.BigEndian.PutUint16(lenght, uint16(len(payload)))
		return append(lenght, payload...)
	default:
		// nothing to do for udp
		return payload
	}
}

func isBadAuthReply(b []byte) bool {
	return bytes.Equal(b[:len(serverBadAuth)], serverBadAuth)
}

func isPushReply(b []byte) bool {
	return bytes.Equal(b[:len(serverPushReply)], serverPushReply)
}
