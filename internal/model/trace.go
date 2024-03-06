package model

import (
	"fmt"
	"time"
)

// HandshakeTracer allows to collect traces for a given OpenVPN handshake. A HandshakeTracer can be optionally
// added to the top-level TUN constructor, and it will be propagated to any layer that needs to register an event.
type HandshakeTracer interface {
	// TimeNow allows to inject time for deterministic tests.
	TimeNow() time.Time

	// OnStateChange is called for each transition in the state machine.
	OnStateChange(state NegotiationState)

	// OnIncomingPacket is called when a packet is received.
	OnIncomingPacket(packet *Packet, stage NegotiationState)

	// OnOutgoingPacket is called when a packet is about to be sent.
	OnOutgoingPacket(packet *Packet, stage NegotiationState, retries int)

	// OnDroppedPacket is called whenever a packet is dropped (in/out)
	OnDroppedPacket(direction Direction, stage NegotiationState, packet *Packet)
}

// Direction is one of two directions on a packet.
type Direction int

const (
	// DirectionIncoming marks received packets.
	DirectionIncoming = Direction(iota)

	// DirectionOutgoing marks packets to be sent.
	DirectionOutgoing
)

var _ fmt.Stringer = Direction(0)

// String implements fmt.Stringer
func (d Direction) String() string {
	switch d {
	case DirectionIncoming:
		return "read"
	case DirectionOutgoing:
		return "write"
	default:
		return "undefined"
	}
}

// DummyTracer is a no-op implementation of [model.HandshakeTracer] that does nothing
// but can be safely passed as a default implementation.
type DummyTracer struct{}

// TimeNow allows to manipulate time for deterministic tests.
func (dt DummyTracer) TimeNow() time.Time { return time.Now() }

// OnStateChange is called for each transition in the state machine.
func (dt DummyTracer) OnStateChange(NegotiationState) {}

// OnIncomingPacket is called when a packet is received.
func (dt DummyTracer) OnIncomingPacket(*Packet, NegotiationState) {}

// OnOutgoingPacket is called when a packet is about to be sent.
func (dt DummyTracer) OnOutgoingPacket(*Packet, NegotiationState, int) {}

// OnDroppedPacket is called whenever a packet is dropped (in/out)
func (dt DummyTracer) OnDroppedPacket(Direction, NegotiationState, *Packet) {}

// Assert that dummyTracer implements [model.HandshakeTracer].
var _ HandshakeTracer = &DummyTracer{}
