package vpn

//
// Encode and decode packets according to the OpenVPN protocol.
//

import (
	"bytes"
	"io"
)

type sessionID [8]byte
type ackArray []uint32

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

// packetFromBytes produces a packet after parsing the common header.
// In TCP mode, it is assumed that the packet length part of the header has
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
	return packet
}

// TODO while-refactor -------------------------------
// XXX needed? return a parsed control packet
// should return error if not a control packet too
func newControlPacketFromBytes(buf []byte) *packet {
	p := newPacketFromBytes(buf)
	p = parseControlPacket(p)
	return p
}

// TODO(ainghazal): make it a method?
// serializeControlPacket returns a byte array that is ready to be sent on the
// wire.
// TODO(ainghazal): this function should fail for non-control opcodes.
// TODO(ainghazal): how do data packets work?
func serializeControlPacket(packet *packet) []byte {
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

// parseControlPacket processes
func parseControlPacket(packet *packet) *packet {
	// TODO assert this is indeed a control packet
	buf := bytes.NewBuffer(packet.payload)
	// remote session id
	_, err := io.ReadFull(buf, packet.localSessionID[:])
	if err != nil {
		return nil
	}
	// ack array
	code, err := buf.ReadByte()
	if err != nil {
		return nil
	}

	// TODO: come to terms with acks
	nAcks := int(code)
	packet.acks = make([]uint32, nAcks)
	for i := 0; i < nAcks; i++ {
		packet.acks[i], err = bufReadUint32(buf)
		if err != nil {
			return nil
		}
	}
	// local session id
	if nAcks > 0 {
		_, err = io.ReadFull(buf, packet.remoteSessionID[:])
		if err != nil {
			return nil
		}
	}
	// packet id
	if packet.opcode != pACKV1 {
		packet.id, err = bufReadUint32(buf)
		if err != nil {
			return nil
		}
	}
	// payload
	packet.payload = buf.Bytes()
	return packet
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
