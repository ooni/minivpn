package vpn

//
// Encode and decode packets according to the OpenVPN protocol.
//

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
)

var (
	errEmptyPayload      = errors.New("empty payload")
	errBadKeyMethod      = errors.New("unsupported key method")
	errBadControlMessage = errors.New("bad message")

	controlMessageHeader = []byte{0x00, 0x00, 0x00, 0x00}
)

type sessionID [8]byte
type ackArray []uint32

func (s *sessionID) Bytes() []byte {
	return s[:]
}

type packet struct {
	// opcode is the packet message type (a P_* constant; high 5-bits of
	// the first packet byte).
	opcode byte
	// The key_id refers to an already negotiated TLS session.
	// This is the shortened version of the key-id (low 3-bits of the first packet byte).
	keyID byte
	// id is the packet-id for replay protection (4 or 8 bytes, includes
	// sequence number and optional time_t timestamp).
	id uint32
	// The 64 bit form (of the key) is referred to as a session_id.
	localSessionID  sessionID
	remoteSessionID sessionID
	payload         []byte
	acks            ackArray
}

// TODO(ainghazal): move those methods here

func (p *packet) isACK() bool {
	return isACKOpcode(p.opcode)
}

func (p *packet) isControl() bool {
	return isControlOpcode(p.opcode)
}

func (p *packet) isControlV1() bool {
	return p.opcode == byte(pControlV1)
}

func (p *packet) isData() bool {
	return isDataOpcode(p.opcode)
}

// serverControlMessage is sent by the server. it contains reply to the auth
// and push requests. we initialize client's internal state after parsing the
// fields contained in here.
// TODO does this have a constant type? (can I write a parse function that
// returns the right record?)
type serverControlMessage struct {
	// client.onRemoteOpts()
	// client.onKeyExchanged()
	// client on.PushData()
	// AUTH_FAILED
	payload []byte
}

func (sc *serverControlMessage) valid() bool {
	return bytes.Equal(sc.payload[:4], controlMessageHeader)
}

func newServerControlMessageFromBytes(buf []byte) *serverControlMessage {
	return &serverControlMessage{buf}
}

// parseControlMessage gets a server control message and returns the value for
// the remote key, the server remote options, and an error indicating if the
// operation could not be completed.
func parseServerControlMessage(sc *serverControlMessage) (*keySource, string, error) {
	if !sc.valid() {
		return nil, "", fmt.Errorf("%w: %s", errBadControlMessage, "bad header")
	}
	if len(sc.payload) < 71 {
		return nil, "", fmt.Errorf("%w: bad len from server:%d", errBadControlMessage, len(sc.payload))
	}
	keyMethod := sc.payload[4]
	if keyMethod != 2 {
		return nil, "", fmt.Errorf("%w: %d", errBadKeyMethod, keyMethod)

	}
	// first chunk of random bytes
	r1 := sc.payload[5:37]
	// second chunk of random bytes
	r2 := sc.payload[37:69]
	options, err := decodeOptionStringFromBytes(sc.payload[69:])
	if err != nil {
		log.Printf("ERROR server sent bad options string: %s\n", err.Error())
	}

	log.Println("Remote opts:", options)
	remoteKey := &keySource{r1: r1, r2: r2}
	return remoteKey, options, nil
}

// encodeClientControlMessage returns a byte array with the payload for a control channel packet.
// This is the packet that the client sends to the server with the key
// material, local options and credentials (if username+password authentication is used).
func encodeClientControlMessageAsBytes(k *keySource, o *Options) ([]byte, error) {
	opt, err := encodeOptionStringToBytes(o.String())
	if err != nil {
		return nil, err
	}
	user, err := encodeOptionStringToBytes(string(o.Username))
	if err != nil {
		return nil, err
	}
	pass, err := encodeOptionStringToBytes(string(o.Password))
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	out.Write(controlMessageHeader)
	out.WriteByte(0x02) // key method (2)
	out.Write(k.Bytes())
	out.Write(opt)
	out.Write(user)
	out.Write(pass)
	return out.Bytes(), nil
}

type serverHardReset struct {
	payload []byte
}

func newServerHardReset(b []byte) (*serverHardReset, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("%w: %s", errBadReset, "zero len")
	}
	p := &serverHardReset{b}
	return p, nil
}

// parseServerHardReset returns the sessionID received from the server, or an
// error if we could not parse the message.
func parseServerHardReset(p *serverHardReset) (sessionID, error) {
	s := sessionID{}
	// TODO get the opcode from this, parse packet etc
	// (assumes keyID == 0)
	if p.payload[0] != 0x40 {
		return s, fmt.Errorf("%w: %s", errBadReset, "bad header")
	}
	if len(p.payload) < 10 {
		return s, fmt.Errorf("%w: %s", errBadReset, "not enough bytes")
	}
	var rs sessionID
	copy(rs[:], p.payload[1:9])
	return rs, nil
}

// encodePushRequestAsBytes returns a byte array with the PUSH_REQUEST command.
func encodePushRequestAsBytes() []byte {
	var out bytes.Buffer
	out.Write([]byte("PUSH_REQUEST"))
	out.WriteByte(0x00)
	return out.Bytes()
}

// packetFromBytes produces a packet after parsing the common header.
// In TCP mode, it is assumed that the packet length (part of the header) has
// already been stripped out.
func newPacketFromBytes(buf []byte) *packet {
	if len(buf) < 2 {
		return nil
	}
	packet := &packet{
		opcode: buf[0] >> 3,
		keyID:  buf[0] & 0x07,
	}
	packet.payload = make([]byte, len(buf)-1)
	copy(packet.payload, buf[1:])
	packet.parse()
	return packet
}

// TODO uint8
func newPacketFromPayload(opcode uint8, keyID uint8, payload []byte) *packet {
	packet := &packet{
		opcode:  opcode,
		keyID:   keyID,
		payload: payload,
	}
	return packet
}

// parse tries to parse the payload of the packet. this method can only be
// called once.
// TODO convert into a pure function
func (p *packet) parse() error {
	if p.isControl() {
		p.parseControlPacket()
	}
	return nil
}

// TODO make parsers an interface
// parseControlPacket parses the contents of a packet.
func (p *packet) parseControlPacket() error {
	if len(p.payload) == 0 {
		return errEmptyPayload
	}
	// TODO assert this is indeed a control packet
	buf := bytes.NewBuffer(p.payload)

	// session id
	_, err := io.ReadFull(buf, p.localSessionID[:])
	if err != nil {
		return err
	}
	// ack array
	code, err := buf.ReadByte()
	if err != nil {
		return err
	}

	// TODO: come to terms with acks
	nAcks := int(code)
	p.acks = make([]uint32, nAcks)
	for i := 0; i < nAcks; i++ {
		p.acks[i], err = bufReadUint32(buf)
		if err != nil {
			return nil
		}
	}
	// local session id
	if nAcks > 0 {
		_, err = io.ReadFull(buf, p.remoteSessionID[:])
		if err != nil {
			return nil
		}
	}
	// packet id
	if p.opcode != pACKV1 {
		p.id, err = bufReadUint32(buf)
		if err != nil {
			return nil
		}
	}
	// payload
	p.payload = buf.Bytes()
	return nil
}

// TODO(ainghazal): make it a method?
// serializeControlPacket returns a byte array that is ready to be sent on the
// wire.
// TODO(ainghazal): this function should fail for non-control opcodes.
// TODO(ainghazal): how do data packets work?
func (packet *packet) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte((packet.opcode << 3) | (packet.keyID & 0x07))
	//  local session id --> we take this from the muxer
	buf.Write(packet.localSessionID[:])
	// TODO how do acks work?
	//  acks --> if we have acks for this packet (??),
	// we write a byte with the number of acks, and then
	// serialize each ack.
	// TODO(ainghazal): boundary check, ackArray must be <255.
	buf.WriteByte(byte(len(packet.acks)))
	for i := 0; i < len(packet.acks); i++ {
		bufWriteUint32(buf, packet.acks[i])
	}
	//  remote session id
	if len(packet.acks) > 0 {
		buf.Write(packet.remoteSessionID[:])
	}
	if packet.opcode != pACKV1 {
		bufWriteUint32(buf, packet.id)
	}
	//  payload
	buf.Write(packet.payload)
	return buf.Bytes()
}

// newACKPacket returns a packet with the P_ACK_V1 opcode.
func newACKPacket(ackID uint32, s *session) *packet {
	acks := []uint32{ackID}
	// var localSession, remoteSession sessionID
	// copy(localSession[:], lsid[:8])
	// copy(remoteSession[:], rsid[:8])
	p := &packet{
		opcode:          pACKV1,
		localSessionID:  s.LocalSessionID,
		remoteSessionID: s.RemoteSessionID,
		acks:            acks,
	}
	return p
}

func isControlOpcode(b byte) bool {
	switch b {
	case byte(pControlHardResetServerV2), byte(pControlV1):
		return true
	default:
		return false
	}
}

func isDataOpcode(b byte) bool {
	switch b {
	case byte(pDataV1):
		return true
	default:
		return false
	}
}

func isACKOpcode(b byte) bool {
	return b == byte(pACKV1)
}

//
// TODO
//
// [ ] implement unwrap/decrypt functions for data packets?
// [ ] implement unwrap methods for control packet? (options etc)
