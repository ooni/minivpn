package model

//
// Packet
//
// Parsing and serializing OpenVPN packets.
//

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/ooni/minivpn/internal/bytesx"
)

// Opcode is an OpenVPN packet opcode.
type Opcode byte

// OpenVPN packets opcodes.
const (
	P_CONTROL_HARD_RESET_CLIENT_V1 = Opcode(iota + 1) // 1
	P_CONTROL_HARD_RESET_SERVER_V1                    // 2
	P_CONTROL_SOFT_RESET_V1                           // 3
	P_CONTROL_V1                                      // 4
	P_ACK_V1                                          // 5
	P_DATA_V1                                         // 6
	P_CONTROL_HARD_RESET_CLIENT_V2                    // 7
	P_CONTROL_HARD_RESET_SERVER_V2                    // 8
	P_DATA_V2                                         // 9
)

// NewOpcodeFromString returns an opcode from a string representation, and an error if it cannot parse the opcode
// representation. The zero return value is invalid and always coupled with a non-nil error.
func NewOpcodeFromString(s string) (Opcode, error) {
	switch s {
	case "CONTROL_HARD_RESET_CLIENT_V1":
		return P_CONTROL_HARD_RESET_CLIENT_V1, nil
	case "CONTROL_HARD_RESET_SERVER_V1":
		return P_CONTROL_HARD_RESET_SERVER_V1, nil
	case "CONTROL_SOFT_RESET_V1":
		return P_CONTROL_SOFT_RESET_V1, nil
	case "CONTROL_V1":
		return P_CONTROL_V1, nil
	case "ACK_V1":
		return P_ACK_V1, nil
	case "DATA_V1":
		return P_DATA_V1, nil
	case "CONTROL_HARD_RESET_CLIENT_V2":
		return P_CONTROL_HARD_RESET_CLIENT_V2, nil
	case "CONTROL_HARD_RESET_SERVER_V2":
		return P_CONTROL_HARD_RESET_SERVER_V2, nil
	case "DATA_V2":
		return P_DATA_V2, nil
	default:
		return 0, errors.New("unknown opcode")
	}
}

// String returns the opcode string representation
func (op Opcode) String() string {
	switch op {
	case P_CONTROL_HARD_RESET_CLIENT_V1:
		return "P_CONTROL_HARD_RESET_CLIENT_V1"

	case P_CONTROL_HARD_RESET_SERVER_V1:
		return "P_CONTROL_HARD_RESET_SERVER_V1"

	case P_CONTROL_SOFT_RESET_V1:
		return "P_CONTROL_SOFT_RESET_V1"

	case P_CONTROL_V1:
		return "P_CONTROL_V1"

	case P_ACK_V1:
		return "P_ACK_V1"

	case P_DATA_V1:
		return "P_DATA_V1"

	case P_CONTROL_HARD_RESET_CLIENT_V2:
		return "P_CONTROL_HARD_RESET_CLIENT_V2"

	case P_CONTROL_HARD_RESET_SERVER_V2:
		return "P_CONTROL_HARD_RESET_SERVER_V2"

	case P_DATA_V2:
		return "P_DATA_V2"

	default:
		return "P_UNKNOWN"
	}
}

// IsControl returns true when this opcode is a control opcode.
func (op Opcode) IsControl() bool {
	switch op {
	case P_CONTROL_HARD_RESET_CLIENT_V1,
		P_CONTROL_HARD_RESET_SERVER_V1,
		P_CONTROL_SOFT_RESET_V1,
		P_CONTROL_V1,
		P_CONTROL_HARD_RESET_CLIENT_V2,
		P_CONTROL_HARD_RESET_SERVER_V2:
		return true
	default:
		return false
	}
}

// IsData returns true when this opcode is a data opcode.
func (op Opcode) IsData() bool {
	switch op {
	case P_DATA_V1, P_DATA_V2:
		return true
	default:
		return false
	}
}

// SessionID is the session identifier.
type SessionID [8]byte

// PacketID is a packet identifier.
type PacketID uint32

// PeerID is the type of the P_DATA_V2 peer ID.
type PeerID [3]byte

// Packet is an OpenVPN packet.
type Packet struct {
	// Opcode is the packet message type (a P_* constant; high 5-bits of
	// the first packet byte).
	Opcode Opcode

	// The key_id refers to an already negotiated TLS session.
	// This is the shortened version of the key-id (low 3-bits of the first
	// packet byte).
	KeyID byte

	// PeerID is the peer ID.
	PeerID PeerID

	// LocalSessionID is the local session ID.
	LocalSessionID SessionID

	// Acks contains the remote packets we're ACKing.
	ACKs []PacketID

	// RemoteSessionID is the remote session ID.
	RemoteSessionID SessionID

	// ID is the packet-id for replay protection. According to the spec: "4 or 8 bytes,
	// includes sequence number and optional time_t timestamp".
	//
	// This library does not use the timestamp.
	ID PacketID

	// Payload is the packet's payload.
	Payload []byte
}

// ErrPacketTooShort indicates that a packet is too short.
var ErrPacketTooShort = errors.New("openvpn: packet too short")

// ParsePacket produces a packet after parsing the common header. We assume that
// the underlying connection has already stripped out the framing.
func ParsePacket(buf []byte) (*Packet, error) {
	// parsing opcode and keyID
	if len(buf) < 2 {
		return nil, ErrPacketTooShort
	}
	opcode := Opcode(buf[0] >> 3)
	keyID := buf[0] & 0x07

	// extract the packet payload and possibly the peerID
	var (
		payload []byte
		peerID  PeerID
	)
	switch opcode {
	case P_DATA_V2:
		if len(buf) < 4 {
			return nil, ErrPacketTooShort
		}
		copy(peerID[:], buf[1:4])
		payload = buf[4:]
	default:
		payload = buf[1:]
	}

	// ACKs and control packets require more complex parsing
	if opcode.IsControl() || opcode == P_ACK_V1 {
		return parseControlOrACKPacket(opcode, keyID, payload)
	}

	// otherwise just return the data packet.
	p := &Packet{
		Opcode:          opcode,
		KeyID:           keyID,
		PeerID:          peerID,
		LocalSessionID:  [8]byte{},
		ACKs:            []PacketID{},
		RemoteSessionID: [8]byte{},
		ID:              0,
		Payload:         payload,
	}
	return p, nil
}

// ErrEmptyPayload indicates tha the payload of an OpenVPN control packet is empty.
var ErrEmptyPayload = errors.New("openvpn: empty payload")

// ErrParsePacket is a generic packet parse error which may be further qualified.
var ErrParsePacket = errors.New("openvpn: packet parse error")

// parseControlOrACKPacket parses the contents of a control or ACK packet.
func parseControlOrACKPacket(opcode Opcode, keyID byte, payload []byte) (*Packet, error) {
	// make sure we have payload to parse and we're parsing control or ACK
	if len(payload) <= 0 {
		return nil, ErrEmptyPayload
	}
	if !opcode.IsControl() && opcode != P_ACK_V1 {
		return nil, fmt.Errorf("%w: %s", ErrParsePacket, "expected control/ack packet")
	}

	// create a buffer for parsing the packet
	buf := bytes.NewBuffer(payload)

	p := NewPacket(opcode, keyID, payload)

	// local session id
	if _, err := io.ReadFull(buf, p.LocalSessionID[:]); err != nil {
		return p, fmt.Errorf("%w: bad sessionID: %s", ErrParsePacket, err)
	}

	// ack array length
	ackArrayLenByte, err := buf.ReadByte()
	if err != nil {
		return p, fmt.Errorf("%w: bad ack: %s", ErrParsePacket, err)
	}
	ackArrayLen := int(ackArrayLenByte)

	// ack array
	p.ACKs = make([]PacketID, ackArrayLen)
	for i := 0; i < ackArrayLen; i++ {
		val, err := bytesx.ReadUint32(buf)
		if err != nil {
			return p, fmt.Errorf("%w: cannot parse ack id: %s", ErrParsePacket, err)
		}
		p.ACKs[i] = PacketID(val)
	}

	// remote session id
	if ackArrayLen > 0 {
		if _, err = io.ReadFull(buf, p.RemoteSessionID[:]); err != nil {
			return p, fmt.Errorf("%w: bad remote sessionID: %s", ErrParsePacket, err)
		}
	}

	// packet id
	if p.Opcode != P_ACK_V1 {
		val, err := bytesx.ReadUint32(buf)
		if err != nil {
			return p, fmt.Errorf("%w: bad packetID: %s", ErrParsePacket, err)
		}
		p.ID = PacketID(val)
	}

	// payload
	p.Payload = buf.Bytes()
	return p, nil
}

// NewPacket returns a packet from the passed arguments: opcode, keyID and a raw payload.
func NewPacket(opcode Opcode, keyID uint8, payload []byte) *Packet {
	return &Packet{
		Opcode:          opcode,
		KeyID:           keyID,
		PeerID:          [3]byte{},
		LocalSessionID:  [8]byte{},
		ACKs:            []PacketID{},
		RemoteSessionID: [8]byte{},
		ID:              0,
		Payload:         payload,
	}
}

// ErrMarshalPacket is the error returned when we cannot marshal a packet.
var ErrMarshalPacket = errors.New("openvpn: cannot marshal packet")

// Bytes returns a byte array that is ready to be sent on the wire.
func (p *Packet) Bytes() ([]byte, error) {
	buf := &bytes.Buffer{}

	switch p.Opcode {
	case P_DATA_V2:
		// we assume this is an encrypted data packet,
		// so we serialize just the encrypted payload

	default:
		buf.WriteByte((byte(p.Opcode) << 3) | (p.KeyID & 0x07))
		buf.Write(p.LocalSessionID[:])
		// we write a byte with the number of acks, and then serialize each ack.
		nAcks := len(p.ACKs)
		if nAcks > math.MaxUint8 {
			return nil, fmt.Errorf("%w: too many ACKs", ErrMarshalPacket)
		}
		buf.WriteByte(byte(nAcks))
		for i := 0; i < nAcks; i++ {
			bytesx.WriteUint32(buf, uint32(p.ACKs[i]))
		}
		// remote session id
		if len(p.ACKs) > 0 {
			buf.Write(p.RemoteSessionID[:])
		}
		if p.Opcode != P_ACK_V1 {
			bytesx.WriteUint32(buf, uint32(p.ID))
		}
	}
	//  payload
	buf.Write(p.Payload)
	return buf.Bytes(), nil
}

// IsControl returns true if the packet is any of the control types.
func (p *Packet) IsControl() bool {
	return p.Opcode.IsControl()
}

// IsData returns true if the packet is of data type.
func (p *Packet) IsData() bool {
	return p.Opcode.IsData()
}

// Log writes an entry in the passed logger with a representation of this packet.
func (p *Packet) Log(logger Logger, direction Direction) {
	var dir string
	switch direction {
	case DirectionIncoming:
		dir = "<"
	case DirectionOutgoing:
		dir = ">"
	default:
		logger.Warnf("wrong direction: %d", direction)
		return
	}

	logger.Debugf(
		"%s %s {id=%d, acks=%v} localID=%x remoteID=%x [%d bytes]",
		dir,
		p.Opcode,
		p.ID,
		p.ACKs,
		p.LocalSessionID,
		p.RemoteSessionID,
		len(p.Payload),
	)
}
