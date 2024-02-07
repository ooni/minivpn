package model

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ooni/minivpn/internal/optional"
)

// HandshakeTracer allows to collect traces for a given OpenVPN handshake. A HandshakeTracer can be optionally
// added to the top-level TUN constructor, and it will be propagated to any layer that needs to register an event.
type HandshakeTracer interface {
	// TimeNow allows to inject time for deterministic tests.
	TimeNow() time.Time

	// OnStateChange is called for each transition in the state machine.
	OnStateChange(state int)

	// OnIncomingPacket is called when a packet is received.
	OnIncomingPacket(packet *Packet)

	// OnOutgoingPacket is called when a packet is about to be sent.
	OnOutgoingPacket(packet *Packet, retries int)

	// OnDroppedPacket is called whenever a packet is dropped (in/out)
	OnDroppedPacket(direction Direction, packet *Packet)

	// OnHandshakeDone is called when we have completed a handshake.
	OnHandshakeDone(remoteAddr string)

	// Trace returns an array of [HandshakeEvent]s.
	Trace() []HandshakeEvent
}

const (
	HandshakeEventStateChange = iota
	HandshakeEventPacketIn
	HandshakeEventPacketOut
	HandshakeEventPacketDropped
)

// HandshakeEventType indicates which event we logged.
type HandshakeEventType int

// Ensure that it implements the Stringer interface.
var _ fmt.Stringer = HandshakeEventType(0)

// String implements fmt.Stringer
func (e HandshakeEventType) String() string {
	switch e {
	case HandshakeEventStateChange:
		return "state"
	case HandshakeEventPacketIn:
		return "packet_in"
	case HandshakeEventPacketOut:
		return "packet_out"
	case HandshakeEventPacketDropped:
		return "packet_dropped"
	default:
		return "unknown"
	}
}

// HandshakeEvent must implement the event annotation methods, plus json serialization.
type HandshakeEvent interface {
	Type() HandshakeEventType
	Time() time.Time
	Packet() optional.Value[LoggedPacket]
	json.Marshaler
}

// LoggedPacket tracks metadata about a packet useful to build traces.
type LoggedPacket struct {
	Direction Direction

	// the only fields of the packet we want to log.
	Opcode Opcode
	ID     PacketID
	ACKs   []PacketID

	// PayloadSize is the size of the payload in bytes
	PayloadSize int

	// Retries keeps track of packet retransmission (only for outgoing packets).
	Retries int
}

// MarshalJSON implements json.Marshaler.
func (lp LoggedPacket) MarshalJSON() ([]byte, error) {
	j := struct {
		Opcode      string     `json:"opcode"`
		ID          PacketID   `json:"id"`
		ACKs        []PacketID `json:"acks"`
		Direction   string     `json:"direction"`
		PayloadSize int        `json:"payload_size"`
		Retries     int        `json:"send_attempts"`
	}{
		Opcode:      lp.Opcode.String(),
		ID:          lp.ID,
		ACKs:        lp.ACKs,
		Direction:   lp.Direction.String(),
		PayloadSize: lp.PayloadSize,
		Retries:     lp.Retries,
	}
	return json.Marshal(j)
}

// Direction is one of two directions on a packet.
type Direction int

const (
	// DirectionIncoming marks received packets.
	DirectionIncoming = iota

	// DirectionOutgoing marks packets to be sent.
	DirectionOutgoing
)

var _ fmt.Stringer = Direction(0)

// String implements fmt.Stringer
func (d Direction) String() string {
	switch d {
	case DirectionIncoming:
		return "recv"
	case 1:
		return "send"
	default:
		return "undefined"
	}
}

// dummyTracer is a no-op implementation of [model.HandshakeTracer] that does nothing
// but can be safely passed as a default implementation.
type dummyTracer struct{}

// TimeNow allows to manipulate time for deterministic tests.
func (dt *dummyTracer) TimeNow() time.Time { return time.Now() }

// OnStateChange is called for each transition in the state machine.
func (dt *dummyTracer) OnStateChange(state int) {}

// OnIncomingPacket is called when a packet is received.
func (dt *dummyTracer) OnIncomingPacket(packet *Packet) {}

// OnOutgoingPacket is called when a packet is about to be sent.
func (dt *dummyTracer) OnOutgoingPacket(packet *Packet, retries int) {}

// OnDroppedPacket is called whenever a packet is dropped (in/out)
func (dt *dummyTracer) OnDroppedPacket(direction Direction, packet *Packet) {
}

func (dt *dummyTracer) OnHandshakeDone(remoteAddr string) {}

// Trace returns a structured log containing an array of [model.HandshakeEvent].
func (dt *dummyTracer) Trace() []HandshakeEvent { return []HandshakeEvent{} }

// Assert that dummyTracer implements [model.HandshakeTracer].
var _ HandshakeTracer = &dummyTracer{}
