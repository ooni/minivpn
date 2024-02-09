// Package tracex implements a handshake tracer that can be passed to the TUN constructor to
// observe handshake events.
package tracex

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/optional"
)

// event is one handshake event collected by this [model.HandshakeTracer].
type event struct {
	// EventType is the type for this event.
	EventType HandshakeEventType

	// AtTime is the time for this event, relative to the start time.
	AtTime time.Time

	DeltaTime time.Duration

	// LoggedPacket is an optional packet metadata.
	LoggedPacket optional.Value[LoggedPacket]
}

func newEvent(etype HandshakeEventType, t time.Time, t0 time.Time) *event {
	return &event{
		EventType:    etype,
		AtTime:       t,
		DeltaTime:    t.Sub(t0),
		LoggedPacket: optional.None[LoggedPacket](),
	}
}

// MarshalJSON implements json.Marshaler
func (e event) MarshalJSON() ([]byte, error) {
	j := struct {
		Type   string       `json:"type"`
		Time   time.Time    `json:"t"`
		Packet LoggedPacket `json:"packet"`
	}{
		Type:   e.EventType.String(),
		Time:   e.AtTime,
		Packet: e.LoggedPacket.Unwrap(),
	}
	return json.Marshal(j)
}

// Tracer implements [model.HandshakeTracer].
type Tracer struct {
	// events is the array of handshake events.
	events []*event

	// mu guards access to the events.
	mu sync.Mutex

	// zeroTime is the time when we started a packet trace.
	zeroTime time.Time
}

// NewTracer returns a Tracer with the passed start time.
func NewTracer(start time.Time) *Tracer {
	return &Tracer{
		zeroTime: start,
	}
}

// TimeNow allows to manipulate time for deterministic tests.
func (t *Tracer) TimeNow() time.Time {
	return time.Now()
}

// OnStateChange is called for each transition in the state machine.
func (t *Tracer) OnStateChange(state int) {
	panic("not implemented") // TODO: Implement
}

// OnIncomingPacket is called when a packet is received.
func (t *Tracer) OnIncomingPacket(packet *model.Packet) {
	t.mu.Lock()
	defer t.mu.Unlock()

	e := newEvent(handshakeEventPacketIn, t.TimeNow(), t.zeroTime)
	e.LoggedPacket = logPacket(packet, -1, model.DirectionIncoming)
	t.events = append(t.events, e)
}

// OnOutgoingPacket is called when a packet is about to be sent.
func (t *Tracer) OnOutgoingPacket(packet *model.Packet, retries int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	e := newEvent(handshakeEventPacketOut, t.TimeNow(), t.zeroTime)
	e.LoggedPacket = logPacket(packet, retries, model.DirectionOutgoing)
	t.events = append(t.events, e)
}

// OnDroppedPacket is called whenever a packet is dropped (in/out)
func (t *Tracer) OnDroppedPacket(direction model.Direction, packet *model.Packet) {
	// panic("not implemented") // TODO: Implement
}

func (t *Tracer) OnHandshakeDone(remoteAddr string) {
	panic("not implemented") // TODO: Implement
}

// Trace returns a structured log containing a copy of the array of [model.HandshakeEvent].
func (t *Tracer) Trace() []*event {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]*event{}, t.events...)
}

func logPacket(p *model.Packet, retries int, direction model.Direction) optional.Value[LoggedPacket] {
	return optional.Some(LoggedPacket{
		Opcode:      p.Opcode,
		ID:          p.ID,
		ACKs:        p.ACKs,
		Direction:   direction,
		PayloadSize: len(p.Payload),
		Retries:     retries,
	})
}

const (
	handshakeEventStateChange = iota
	handshakeEventPacketIn
	handshakeEventPacketOut
	handshakeEventPacketDropped
)

// HandshakeEventType indicates which event we logged.
type HandshakeEventType int

// Ensure that it implements the Stringer interface.
var _ fmt.Stringer = HandshakeEventType(0)

// String implements fmt.Stringer
func (e HandshakeEventType) String() string {
	switch e {
	case handshakeEventStateChange:
		return "state"
	case handshakeEventPacketIn:
		return "packet_in"
	case handshakeEventPacketOut:
		return "packet_out"
	case handshakeEventPacketDropped:
		return "packet_dropped"
	default:
		return "unknown"
	}
}

// LoggedPacket tracks metadata about a packet useful to build traces.
type LoggedPacket struct {
	Direction model.Direction

	// the only fields of the packet we want to log.
	Opcode model.Opcode
	ID     model.PacketID
	ACKs   []model.PacketID

	// PayloadSize is the size of the payload in bytes
	PayloadSize int

	// Retries keeps track of packet retransmission (only for outgoing packets).
	// TODO: use optional here.
	Retries int
}

// MarshalJSON implements json.Marshaler.
func (lp LoggedPacket) MarshalJSON() ([]byte, error) {
	j := struct {
		Direction   string           `json:"direction"`
		Opcode      string           `json:"opcode"`
		ID          model.PacketID   `json:"id"`
		ACKs        []model.PacketID `json:"acks"`
		PayloadSize int              `json:"payload_size"`
		Retries     int              `json:"send_attempts"`
	}{
		Direction:   lp.Direction.String(),
		Opcode:      lp.Opcode.String(),
		ID:          lp.ID,
		ACKs:        lp.ACKs,
		PayloadSize: lp.PayloadSize,
		Retries:     lp.Retries,
	}
	return json.Marshal(j)
}