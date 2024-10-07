// Package tracex implements a handshake tracer that can be passed to the TUN constructor to
// observe handshake events.
package tracex

import (
	"fmt"
	"sync"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/optional"
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

// Event is a handshake event collected by this [model.HandshakeTracer].
type Event struct {
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

	// TransactionID is an optional index identifying one particular handshake.
	TransactionID int64 `json:"transaction_id,omitempty"`
}

type NegotiationState = model.NegotiationState

func newEvent(etype HandshakeEventType, st NegotiationState, t time.Time, t0 time.Time, txid int64) *Event {
	return &Event{
		EventType:     etype.String(),
		Stage:         st.String()[2:],
		AtTime:        t.Sub(t0).Seconds(),
		Tags:          make([]string, 0),
		LoggedPacket:  optional.None[LoggedPacket](),
		TransactionID: txid,
	}
}

// Tracer implements [model.HandshakeTracer].
type Tracer struct {
	// events is the array of handshake events.
	events []*Event

	// mu guards access to the events.
	mu sync.Mutex

	// transactionID is an optional index that will be added to any events produced by this tracer.
	transactionID int64

	// zeroTime is the time when we started a packet trace.
	zeroTime time.Time
}

// NewTracer returns a Tracer with the passed start time.
func NewTracer(start time.Time) *Tracer {
	return &Tracer{
		zeroTime: start,
	}
}

// NewTracerWithTransactionID returns a Tracer with the passed start time and the given
// identifier for a transaction. Transaction IDs are meant as a convenience to use
// this tracer out-of-the-box from within the ooni probes, and it follows the expected
// semantics to cross-reference measurements.
func NewTracerWithTransactionID(start time.Time, txid int64) *Tracer {
	return &Tracer{
		transactionID: txid,
		zeroTime:      start,
	}
}

// TimeNow allows to manipulate time for deterministic tests.
func (t *Tracer) TimeNow() time.Time {
	return time.Now()
}

// OnStateChange is called for each transition in the state machine.
func (t *Tracer) OnStateChange(state NegotiationState) {
	t.mu.Lock()
	defer t.mu.Unlock()

	e := newEvent(handshakeEventStateChange, state, t.TimeNow(), t.zeroTime, t.transactionID)
	t.events = append(t.events, e)
}

// OnIncomingPacket is called when a packet is received.
func (t *Tracer) OnIncomingPacket(packet *model.Packet, stage NegotiationState) {
	t.mu.Lock()
	defer t.mu.Unlock()

	e := newEvent(handshakeEventPacketIn, stage, t.TimeNow(), t.zeroTime, t.transactionID)
	e.LoggedPacket = logPacket(packet, optional.None[int](), model.DirectionIncoming)
	maybeAddTagsFromPacket(e, packet)
	t.events = append(t.events, e)
}

// OnOutgoingPacket is called when a packet is about to be sent.
func (t *Tracer) OnOutgoingPacket(packet *model.Packet, stage NegotiationState, retries int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	e := newEvent(handshakeEventPacketOut, stage, t.TimeNow(), t.zeroTime, t.transactionID)
	e.LoggedPacket = logPacket(packet, optional.Some(retries), model.DirectionOutgoing)
	maybeAddTagsFromPacket(e, packet)
	t.events = append(t.events, e)
}

// OnDroppedPacket is called whenever a packet is dropped (in/out)
func (t *Tracer) OnDroppedPacket(direction model.Direction, stage NegotiationState, packet *model.Packet) {
	t.mu.Lock()
	defer t.mu.Unlock()

	e := newEvent(handshakeEventPacketDropped, stage, t.TimeNow(), t.zeroTime, t.transactionID)
	e.LoggedPacket = logPacket(packet, optional.None[int](), direction)
	t.events = append(t.events, e)
}

// Trace returns a structured log containing a copy of the array of [model.HandshakeEvent].
func (t *Tracer) Trace() []*Event {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]*Event{}, t.events...)
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
func maybeAddTagsFromPacket(e *Event, packet *model.Packet) {
	if len(packet.Payload) <= 0 {
		return
	}
	p := packet.Payload
	if len(p) < 6 {
		return
	}
	if p[0] == 0x16 && p[5] == 0x01 {
		e.Tags = append(e.Tags, "client_hello")
		return
	}
	if p[0] == 0x16 && p[5] == 0x02 {
		e.Tags = append(e.Tags, "server_hello")
		return
	}
}
