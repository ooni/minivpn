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
	OnStateChange(state int)

	// OnIncomingPacket is called when a packet is received.
	OnIncomingPacket(packet *Packet, stage int)

	// OnOutgoingPacket is called when a packet is about to be sent.
	OnOutgoingPacket(packet *Packet, stage int, retries int)

	// OnDroppedPacket is called whenever a packet is dropped (in/out)
	OnDroppedPacket(direction Direction, stage int, packet *Packet)
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
func (dt *dummyTracer) OnIncomingPacket(*Packet, int) {}

// OnOutgoingPacket is called when a packet is about to be sent.
func (dt *dummyTracer) OnOutgoingPacket(*Packet, int, int) {}

// OnDroppedPacket is called whenever a packet is dropped (in/out)
func (dt *dummyTracer) OnDroppedPacket(Direction, int, *Packet) {
}

func (dt *dummyTracer) OnHandshakeDone(remoteAddr string) {}

// Assert that dummyTracer implements [model.HandshakeTracer].
var _ HandshakeTracer = &dummyTracer{}
