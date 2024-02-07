// Package tracex implements a [model.HandshakeTracer] that can be passed to the TUN constructor to
// observe handshake events.
package tracex

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/optional"
)

// event implements [model.HandshakeEvent]
type event struct {
	// EventType is the type for this event.
	eventType model.HandshakeEventType

	// AtTime is the time for this event, relative to the start time.
	atTime time.Time

	// TODO: discuss: do we want both?
	deltaTime time.Duration

	// loggedPacket is an optional packet metadata.
	loggedPacket optional.Value[model.LoggedPacket]
}

func newEvent(etype model.HandshakeEventType, t time.Time, t0 time.Time) *event {
	return &event{
		eventType:    etype,
		atTime:       t,
		deltaTime:    t.Sub(t0),
		loggedPacket: optional.None[model.LoggedPacket](),
	}
}

// Type returns the type for the event.
func (e event) Type() model.HandshakeEventType {
	return e.eventType
}

// Time returns the event timestamp.
func (e event) Time() time.Time {
	return e.atTime
}

// Packet returns an optional logged packet.
func (e event) Packet() optional.Value[model.LoggedPacket] {
	return e.loggedPacket
}

// MarshalJSON implements json.Marshaler
func (e event) MarshalJSON() ([]byte, error) {
	j := struct {
		Type   string             `json:"type"`
		Time   time.Time          `json:"t"`
		Packet model.LoggedPacket `json:"packet"`
	}{
		Type:   e.Type().String(),
		Time:   e.Time(),
		Packet: e.Packet().Unwrap(),
	}
	return json.Marshal(j)
}

var _ model.HandshakeEvent = event{}

// Tracer implements [model.HandshakeTracer].
type Tracer struct {
	// events is an array of handshake events.
	events []model.HandshakeEvent

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

	e := newEvent(model.HandshakeEventPacketIn, t.TimeNow(), t.zeroTime)
	e.loggedPacket = logPacket(packet, -1, model.DirectionIncoming)
	t.events = append(t.events, e)
}

// OnOutgoingPacket is called when a packet is about to be sent.
func (t *Tracer) OnOutgoingPacket(packet *model.Packet, retries int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	e := newEvent(model.HandshakeEventPacketOut, t.TimeNow(), t.zeroTime)
	e.loggedPacket = logPacket(packet, retries, model.DirectionOutgoing)
	t.events = append(t.events, e)
}

// OnDroppedPacket is called whenever a packet is dropped (in/out)
func (t *Tracer) OnDroppedPacket(direction model.Direction, packet *model.Packet) {
	// panic("not implemented") // TODO: Implement
}

func (t *Tracer) OnHandshakeDone(remoteAddr string) {
	panic("not implemented") // TODO: Implement
}

// Trace returns a structured log containing an array of [model.HandshakeEvent].
func (t *Tracer) Trace() []model.HandshakeEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.events
}

func logPacket(p *model.Packet, retries int, direction model.Direction) optional.Value[model.LoggedPacket] {
	return optional.Some(model.LoggedPacket{
		Opcode:      p.Opcode,
		ID:          p.ID,
		ACKs:        p.ACKs,
		Direction:   direction,
		PayloadSize: len(p.Payload),
		Retries:     retries,
	})
}
