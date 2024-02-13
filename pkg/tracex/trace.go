// Package tracex implements a handshake tracer that can be passed to the TUN constructor to
// observe handshake events.
package tracex

import (
	"fmt"
	"sync"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/optional"
	"github.com/ooni/minivpn/internal/session"
)

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

// event is a handshake event collected by this [model.HandshakeTracer].
type event struct {
	// EventType is the type for this event.
	EventType string `json:"operation"`

	// Stage is the stage of the handshake negotiation we're in.
	Stage string `json:"stage"`

	// AtTime is the time for this event, relative to the start time.
	AtTime float64 `json:"t"`

	// Tags is an array of tags that can be useful to interpret this event, like the contents of the packet.
	Tags []string `json:"tags"`

	// LoggedPacket is an optional packet metadata.
	LoggedPacket optional.Value[LoggedPacket] `json:"packet"`
}

func newEvent(etype HandshakeEventType, st session.SessionNegotiationState, t time.Time, t0 time.Time) *event {
	return &event{
		EventType:    etype.String(),
		Stage:        st.String()[2:],
		AtTime:       t.Sub(t0).Seconds(),
		Tags:         make([]string, 0),
		LoggedPacket: optional.None[LoggedPacket](),
	}
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
	t.mu.Lock()
	defer t.mu.Unlock()

	stg := session.SessionNegotiationState(state)
	e := newEvent(handshakeEventStateChange, stg, t.TimeNow(), t.zeroTime)
	t.events = append(t.events, e)
}

// OnIncomingPacket is called when a packet is received.
func (t *Tracer) OnIncomingPacket(packet *model.Packet, stage int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	stg := session.SessionNegotiationState(stage)
	e := newEvent(handshakeEventPacketIn, stg, t.TimeNow(), t.zeroTime)
	e.LoggedPacket = logPacket(packet, optional.None[int](), model.DirectionIncoming)
	maybeAddTagsFromPacket(e, packet)
	t.events = append(t.events, e)
}

// OnOutgoingPacket is called when a packet is about to be sent.
func (t *Tracer) OnOutgoingPacket(packet *model.Packet, stage int, retries int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	stg := session.SessionNegotiationState(stage)
	e := newEvent(handshakeEventPacketOut, stg, t.TimeNow(), t.zeroTime)
	e.LoggedPacket = logPacket(packet, optional.Some(retries), model.DirectionOutgoing)
	maybeAddTagsFromPacket(e, packet)
	t.events = append(t.events, e)
}

// OnDroppedPacket is called whenever a packet is dropped (in/out)
func (t *Tracer) OnDroppedPacket(direction model.Direction, stage int, packet *model.Packet) {
	t.mu.Lock()
	defer t.mu.Unlock()

	stg := session.SessionNegotiationState(stage)
	e := newEvent(handshakeEventPacketDropped, stg, t.TimeNow(), t.zeroTime)
	e.LoggedPacket = logPacket(packet, optional.None[int](), direction)
	t.events = append(t.events, e)
}

// Trace returns a structured log containing a copy of the array of [model.HandshakeEvent].
func (t *Tracer) Trace() []*event {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]*event{}, t.events...)
}

func logPacket(p *model.Packet, retries optional.Value[int], direction model.Direction) optional.Value[LoggedPacket] {
	logged := LoggedPacket{
		Opcode:      p.Opcode.String(),
		ID:          p.ID,
		ACKs:        optional.None[[]model.PacketID](),
		Direction:   direction.String(),
		PayloadSize: len(p.Payload),
		Retries:     retries,
	}
	if len(p.ACKs) != 0 {
		logged.ACKs = optional.Some(p.ACKs)
	}
	return optional.Some(logged)
}

// LoggedPacket tracks metadata about a packet useful to build traces.
type LoggedPacket struct {
	Direction string `json:"operation"`

	// the only fields of the packet we want to log.
	Opcode string                           `json:"opcode"`
	ID     model.PacketID                   `json:"id"`
	ACKs   optional.Value[[]model.PacketID] `json:"acks"`

	// PayloadSize is the size of the payload in bytes
	PayloadSize int `json:"payload_size"`

	// Retries keeps track of packet retransmission (only for outgoing packets).
	Retries optional.Value[int] `json:"send_attempts"`
}

// maybeAddTagsFromPacket attempts to derive meaningful tags from
// the packet payload, and adds it to the tag array in the passed event.
func maybeAddTagsFromPacket(e *event, packet *model.Packet) {
	if len(packet.Payload) <= 0 {
		return
	}
	p := packet.Payload
	if p[0] == 0x16 && p[5] == 0x01 {
		e.Tags = append(e.Tags, "client_hello")
		return
	}
	if p[0] == 0x16 && p[5] == 0x02 {
		e.Tags = append(e.Tags, "server_hello")
		return
	}
}
