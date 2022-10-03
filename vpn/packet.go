package vpn

//
// Encode and decode packets according to the OpenVPN protocol.
//

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

const (
	stNothing = iota
	stControlChannelOpen
	stControlMessageSent
	stKeyExchanged
	stPullRequestSent
	stOptionsPushed
	stInitialized
	stDataReady
)

const (
	pControlHardResetClientV1 = iota + 1
	pControlHardResetServerV1 // 2
	pControlSoftResetV1       // 3
	pControlV1                // 4
	pACKV1                    // 5
	pDataV1                   // 6
	pControlHardResetClientV2 // 7
	pControlHardResetServerV2 // 8
	pDataV2                   // 9
)

const (
	UDPMode = iota
	TCPMode
)

var (
	errEmptyPayload      = errors.New("empty payload")
	errBadKeyMethod      = errors.New("unsupported key method")
	errBadControlMessage = errors.New("bad message")
	errBadServerReply    = errors.New("bad server reply")
	errBadAuth           = errors.New("server says: bad auth")

	controlMessageHeader = []byte{0x00, 0x00, 0x00, 0x00}
	pingPayload          = []byte{0x2A, 0x18, 0x7B, 0xF3, 0x64, 0x1E, 0xB4, 0xCB, 0x07, 0xED, 0x2D, 0x0A, 0x98, 0x1F, 0xC7, 0x48}

	IV_Ver   = "2.5.5" // OpenVPN version compat that we declare to the server
	IV_Proto = "2"     // IV_PROTO declared to the server. We need to be sure to enable the peer-id bit to use P_DATA_V2.
)

// sessionID is the session identifier.
type sessionID [8]byte

// packetID is a packet identifier.
type packetID uint32

// ackArray holds the identifiers of packets to ack.
type ackArray []packetID

// packet represents a packet according to the OpenVPN protocol.
type packet struct {

	// id is the packet-id for replay protection.
	// According to the spec: "4 or 8 bytes, includes sequence number and optional time_t timestamp".
	// We do not use the timestamp.
	id packetID

	// opcode is the packet message type (a P_* constant; high 5-bits of
	// the first packet byte).
	opcode byte

	// The key_id refers to an already negotiated TLS session.
	// This is the shortened version of the key-id (low 3-bits of the first
	// packet byte).
	keyID byte

	// The 64 bit form (of the key) is referred to as a session_id.
	localSessionID  sessionID
	remoteSessionID sessionID
	payload         []byte
	acks            ackArray
}

// parsePacketFromBytes produces a packet after parsing the common header.
// In TCP mode, it is assumed that the packet length (part of the header) has
// already been stripped out.
func parsePacketFromBytes(buf []byte) (*packet, error) {
	if len(buf) < 2 {
		return &packet{}, errBadInput
	}
	opcode := buf[0] >> 3
	keyID := buf[0] & 0x07

	var payload = []byte{}

	switch opcode {
	case pDataV2:
		payload = buf[4:]
	default:
		payload = buf[1:]
	}

	// TODO missing peerID
	p := &packet{
		opcode:  opcode,
		keyID:   keyID,
		payload: payload,
	}
	return parsePacket(p)
}

// newPacketFromPayload returns a packet from the passed arguments: opcode,
// keyID and a raw byte array payload.
func newPacketFromPayload(opcode uint8, keyID uint8, payload []byte) *packet {
	p := &packet{
		opcode:  opcode,
		keyID:   keyID,
		payload: payload,
	}
	return p
}

// Bytes returns a byte array that is ready to be sent on the wire.
func (packet *packet) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte((packet.opcode << 3) | (packet.keyID & 0x07))
	buf.Write(packet.localSessionID[:])
	// we write a byte with the number of acks, and then
	// serialize each ack.
	nAcks := len(packet.acks)
	if nAcks > 255 {
		logger.Warnf("packet %d had too many acks (%d)", packet.id, nAcks)
		nAcks = 255
	}
	buf.WriteByte(byte(nAcks))
	for i := 0; i < nAcks; i++ {
		bufWriteUint32(buf, uint32(packet.acks[i]))
	}
	//  remote session id
	if len(packet.acks) > 0 {
		buf.Write(packet.remoteSessionID[:])
	}
	if packet.opcode != pACKV1 {
		bufWriteUint32(buf, uint32(packet.id))
	}
	//  payload
	buf.Write(packet.payload)
	return buf.Bytes()
}

// isACK returns true if the packet is an ACK packet.
func (p *packet) isACK() bool {
	return p.opcode == byte(pACKV1)
}

// isControl returns true if the packet is any of the control types.
func (p *packet) isControl() bool {
	switch p.opcode {
	case byte(pControlHardResetServerV2), byte(pControlV1):
		return true
	default:
		return false
	}
}

// isControlV1 returns true if the packet is of the control v1 type.
func (p *packet) isControlV1() bool {
	return p.opcode == byte(pControlV1)
}

// isData returns true if the packet is of data type.
func (p *packet) isData() bool {
	switch p.opcode {
	case byte(pDataV1), byte(pDataV2):
		return true
	default:
		return false
	}
}

// parse tries to parse the payload of the packet, and returns a packet and an
// error. it does only parse control packets (for now - parsing of data packets
// is done on the data handler methods).
func parsePacket(p *packet) (*packet, error) {
	if p.isControl() {
		return parseControlPacket(p)
	}
	return p, nil
}

// parseControlPacket parses the contents of a control packet, and returns a
// packet and an error.
func parseControlPacket(p *packet) (*packet, error) {
	if len(p.payload) == 0 {
		return p, errEmptyPayload
	}
	if !p.isControl() && !p.isACK() {
		return p, fmt.Errorf("%w: %s", errBadInput, "expected control/ack packet")
	}

	buf := bytes.NewBuffer(p.payload)

	// TODO the error msg will be clearer if we check for the minimum lenght here.

	// local session id
	_, err := io.ReadFull(buf, p.localSessionID[:])
	if err != nil {
		fmt.Println(">>> ", p.localSessionID)
		return p, fmt.Errorf("%w: bad sessionID: %s", errBadInput, err)
	}

	// ack array
	ackBuf, err := buf.ReadByte()
	if err != nil {
		return p, fmt.Errorf("%w: bad ack: %s", errBadInput, err)
	}
	nAcks := int(ackBuf)
	p.acks = make([]packetID, nAcks)
	for i := 0; i < nAcks; i++ {
		val, err := bufReadUint32(buf)
		if err != nil {
			return p, fmt.Errorf("%w: cannot parse ack id: %s", errBadInput, err)
		}
		p.acks[i] = packetID(val)
	}

	// remote session id
	if nAcks > 0 {
		_, err = io.ReadFull(buf, p.remoteSessionID[:])
		if err != nil {
			return p, fmt.Errorf("%w: bad remote sessionID: %s", errBadInput, err)
		}
	}

	// packet id
	if p.opcode != pACKV1 {
		val, err := bufReadUint32(buf)
		if err != nil {
			return p, fmt.Errorf("%w: bad packetID: %s", errBadInput, err)
		}
		p.id = packetID(val)
	}

	// payload
	p.payload = buf.Bytes()
	return p, nil
}

// isPingPacket returns true if the packet payload matches a hard-coded ping
// payload.
func isPing(b []byte) bool {
	return bytes.Equal(b, pingPayload)
}

// serverControlMessage is sent by the server. it contains reply to the auth
// and push requests. we initialize client's internal state after parsing the
// fields contained in here.
type serverControlMessage struct {
	payload []byte
}

// valid returns true if the packet has a control-message header.
func (sc *serverControlMessage) valid() bool {
	if len(sc.payload) < 4 {
		return false
	}
	return bytes.Equal(sc.payload[:4], controlMessageHeader)
}

// newServerControlMessageFromBytes returns a server control message from the
// passed byte array.
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
	var random1, random2 [32]byte
	// first chunk of random bytes
	copy(random1[:], sc.payload[5:37])
	// second chunk of random bytes
	copy(random2[:], sc.payload[37:69])

	options, err := decodeOptionStringFromBytes(sc.payload[69:])
	if err != nil {
		return nil, "", fmt.Errorf("%w:%s", errBadControlMessage, "bad options string")
	}

	logger.Debugf("Remote opts: %s", options)
	remoteKey := &keySource{r1: random1, r2: random2}
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

	// we could send IV_PLAT too, but afaik declaring the platform does not
	// make any difference for our purposes.
	rawInfo := fmt.Sprintf("IV_VER=%s\nIV_PROTO=%s\n", IV_Ver, IV_Proto)
	peerInfo, _ := encodeOptionStringToBytes(rawInfo)
	out.Write(peerInfo)
	return out.Bytes(), nil
}

// serverHard reset contains the payload for a serverHardReset message type.
type serverHardReset struct {
	payload []byte
}

// newServerHardReset returns a serverHardReset message type, and an error if
// the passed payload is empty.
func newServerHardReset(b []byte) (*serverHardReset, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("%w: %s", errBadReset, "zero len")
	}
	p := &serverHardReset{b}
	return p, nil
}

// parseServerHardResetPacket returns the sessionID received from the server, or an
// error if we could not parse the message.
func parseServerHardResetPacket(p *serverHardReset) (sessionID, error) {
	if len(p.payload) < 10 {
		return sessionID{}, fmt.Errorf("%w: %s", errBadReset, "not enough bytes")
	}
	// BUG: this function assumes keyID == 0
	if p.payload[0] != 0x40 {
		return sessionID{}, fmt.Errorf("%w: %s", errBadReset, "bad header")
	}
	var rs sessionID
	copy(rs[:], p.payload[1:9])
	return rs, nil
}

// newACKPacket returns a packet with the P_ACK_V1 opcode.
func newACKPacket(ackID packetID, s *session) *packet {
	acks := []packetID{ackID}
	p := &packet{
		opcode:          pACKV1,
		localSessionID:  s.LocalSessionID,
		remoteSessionID: s.RemoteSessionID,
		acks:            acks,
	}
	return p
}
