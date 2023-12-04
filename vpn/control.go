package vpn

//
// OpenVPN control channel
//

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
	"time"
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

	randomBytes, err := randomFn(8)
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
	fmt.Printf("p.id=%d, s.lastACK=%d\n", p.id, s.lastACK)
	return p.id-s.lastACK == 1
}

// control implements the controlHandler interface.
// Like for true pirates, there is no state in control.
type control struct{}

// SendHardReset sends a control packet with the HardResetClientv2 header,
// over the passed net.Conn.
func (c *control) SendHardReset(conn net.Conn, s *session) error {
	_, err := sendControlPacket(conn, s, pControlHardResetClientV2, 0, []byte(""))
	return err
}

// ParseHardReset extracts the sessionID from a hard-reset server response, and
// an error if the operation was not successful.
func (c *control) ParseHardReset(b []byte) (sessionID, error) {
	p, err := newServerHardReset(b)
	if err != nil {
		return sessionID{}, err
	}
	return parseServerHardResetPacket(p)
}

// PushRequest returns a byte array with the PUSH_REQUEST command.
func (c *control) PushRequest() []byte {
	var out bytes.Buffer
	out.Write([]byte("PUSH_REQUEST"))
	out.WriteByte(0x00)
	return out.Bytes()
}

// ReadReadPushResponse reads a byte array returned from the server,
// as the response to a Push Request, and returns a string containing the
// tunnel IP.
// For now, this is a single string containing _only_ the tunnel ip,
// but we might want to pass a pointer to the tunnel struct in the
// future.
func (*control) ReadPushResponse(b []byte) map[string][]string {
	return pushedOptionsAsMap(b)
}

// ControlMessage returns a byte array containing a message over the control
// channel.
// This is not a P_CONTROL, but a message over the TLS encrypted channel.
func (c *control) ControlMessage(s *session, opt *Options) ([]byte, error) {
	key, err := s.ActiveKey()
	if err != nil {
		return []byte{}, err
	}
	return encodeClientControlMessageAsBytes(key.local, opt)
}

// ReadControlMessage reads a control message with authentication result data.
// it returns the remote key, remote options and an error if we cannot parse
// the data.
func (c *control) ReadControlMessage(b []byte) (*keySource, string, error) {
	cm := newServerControlMessageFromBytes(b)
	return parseServerControlMessage(cm)
}

// SendACK builds an ACK control packet for the given packetID, and writes it
// over the passed connection. It returns an error if the operation cannot be
// completed successfully.
func (c *control) SendACK(conn net.Conn, s *session, pid packetID) error {
	return sendACKFn(conn, s, pid)
}

// sendACK is used by controlHandler.SendACK() and by TLSConn.Read()
func sendACK(conn net.Conn, s *session, pid packetID) error {
	panicIfFalse(len(s.RemoteSessionID) != 0, "tried to ack with null remote")

	//TODO: kostylnoe
	if pid == packetID(4) {
		return nil
	}

	out := append([]byte{0x28}, s.LocalSessionID[:]...)

	ackBytes := binary.BigEndian.AppendUint32([]byte{1}, uint32(pid-1))
	fmt.Println(ackBytes)
	timestamp := uint32(time.Now().Unix())
	timeBytes := binary.BigEndian.AppendUint32(nil, timestamp)
	id, err := s.LocalPacketID()
	if err != nil {
		return nil
	}
	packetIDBytes := binary.BigEndian.AppendUint32(nil, uint32(id))

	secret, _ := hex.DecodeString(secretKey)
	hmacHash := hmac.New(sha1.New, secret[:20])
	hmacHash.Write(packetIDBytes)
	hmacHash.Write(timeBytes)
	hmacHash.Write(out)
	hmacHash.Write(ackBytes)
	hmacHash.Write(s.RemoteSessionID[:])
	hmacResult := hmacHash.Sum(nil)
	out = append(out, hmacResult...)

	out = append(out, packetIDBytes...)
	out = append(out, timeBytes...)
	out = append(out, ackBytes...)
	out = append(out, s.RemoteSessionID[:]...)

	out = maybeAddSizeFrame(conn, out)

	_, err = conn.Write(out)
	if err != nil {
		return err
	}

	logger.Info(fmt.Sprintln("write ack:", pid))
	logger.Debug(fmt.Sprintln(hex.Dump(out)))

	return s.UpdateLastACK(pid)
}

var sendACKFn = sendACK

var _ controlHandler = &control{} // Ensure that we implement controlHandler

// TODO: что-то сделать с этим костылем (сделать парсинг ключа
// TODO: сделать интерфейсы для удобной работы как с tls-auth, так и без
// TODO: возможность работы с различными алгоритмами шифрования
const secretKey = "4c3e03723a0c92509c1c845b604b060a361a45a1886814de50610d824298aedcb8dfc049d0ef381f432ce846a9207ebedacfde77b054a80a330f1e1e3e2897b9"

// sendControlPacket crafts a control packet with the given opcode and payload,
// and writes it to the passed net.Conn.
func sendControlPacket(conn net.Conn, s *session, opcode int, ack int, payload []byte) (n int, err error) {
	if s == nil {
		return 0, fmt.Errorf("%w:%s", errBadInput, "nil session")
	}
	p := newPacketFromPayload(uint8(opcode), 0, payload)
	p.localSessionID = s.LocalSessionID

	s.localPacketID++
	p.id, err = s.LocalPacketID()
	if err != nil {
		return 0, err
	}
	ackBytes := []byte{0, 0, 0, 0, 0}
	timestamp := uint32(time.Now().Unix())
	timeBytes := binary.BigEndian.AppendUint32(nil, timestamp)
	packetIDBytes := binary.BigEndian.AppendUint32(nil, uint32(p.id))

	out := p.Bytes()
	out = []byte{0x38}
	out = append(out, s.LocalSessionID[:]...)

	secret, _ := hex.DecodeString(secretKey)
	hmacHash := hmac.New(sha1.New, secret[:20])
	hmacHash.Write(packetIDBytes)
	hmacHash.Write(timeBytes)
	hmacHash.Write(out)
	hmacHash.Write(ackBytes)
	hmacResult := hmacHash.Sum(nil)
	out = append(out, hmacResult...)

	out = append(out, packetIDBytes...)
	out = append(out, timeBytes...)
	out = append(out, ackBytes...)

	out = maybeAddSizeFrame(conn, out)

	logger.Info(fmt.Sprintf("control write: (%d bytes)\n", len(out)))
	logger.Info(fmt.Sprintln(hex.Dump(out)))
	return conn.Write(out)
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
	case "tcp", "tcp4", "tcp6":
		length := make([]byte, 2)
		binary.BigEndian.PutUint16(length, uint16(len(payload)))
		return append(length, payload...)
	default:
		return []byte{}
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
