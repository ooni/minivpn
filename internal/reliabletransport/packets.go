package reliabletransport

import (
	"fmt"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/optional"
)

//
// A note about terminology: in the following, **receiver** is the moveUpWorker in the [reliabletransport.Service] (since it receives incoming packets), and **sender** is the moveDownWorker in the same service. The following data structures lack mutexes because they are intended to be confined to a single goroutine (one for each worker), and they only communicate via message passing.
//

type inFlightPacket struct {
	// deadline is a moment in time when is this packet scheduled for the next retransmission.
	deadline time.Time

	// how many acks we've received for packets with higher PID.
	higherACKs int

	// packet is the underlying packet being sent.
	packet *model.Packet

	// retries is a monotonically increasing counter for retransmission.
	retries uint8
}

func newInFlightPacket(p *model.Packet) *inFlightPacket {
	return &inFlightPacket{
		deadline:   time.Time{},
		higherACKs: 0,
		packet:     p,
		retries:    0,
	}
}

func (p *inFlightPacket) ExtractACKs() []model.PacketID {
	return p.packet.ACKs
}

// ACKForHigherPacket increments the number of acks received for a higher pid than this packet. This will influence the fast rexmit selection algorithm.
func (p *inFlightPacket) ACKForHigherPacket() {
	p.higherACKs += 1
}

func (p *inFlightPacket) ScheduleForRetransmission(t time.Time) {
	p.retries += 1
	p.deadline = t.Add(p.backoff())
}

// backoff will calculate the next retransmission interval.
func (p *inFlightPacket) backoff() time.Duration {
	backoff := time.Duration(1<<p.retries) * time.Second
	maxBackoff := MAX_BACKOFF_SECONDS * time.Second
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	return backoff
}

// assert that inFlightWrappedPacket implements inFlightPacket and sequentialPacket
// var _ inFlightPacket = &inFlightWrappedPacket{}
// var _ sequentialPacket = &inFlightWrappedPacket{}

// inflightSequence is a sequence of inFlightPackets.
// A inflightSequence can be sorted.
type inflightSequence []*inFlightPacket

// nearestDeadlineTo returns the lower deadline to a passed reference time for all the packets in the inFlight queue. Used to re-arm the Ticker. We need to be careful and not pass a
func (seq inflightSequence) nearestDeadlineTo(t time.Time) time.Time {
	// we default to a long wakeup
	timeout := t.Add(time.Duration(SENDER_TICKER_MS) * time.Millisecond)

	for _, p := range seq {
		if p.deadline.Before(timeout) {
			timeout = p.deadline
		}
	}

	// what's past is past and we need to move on.
	if timeout.Before(t) {
		timeout = t.Add(time.Nanosecond)
	}
	return timeout
}

// readyToSend eturns the subset of this sequence that has a expired deadline or
// is suitable for fast retransmission.
func (seq inflightSequence) readyToSend(t time.Time) inflightSequence {
	expired := make([]*inFlightPacket, 0)
	for _, p := range seq {
		if p.higherACKs >= 3 {
			fmt.Println("DEBUG: fast retransmit for", p.packet.ID)
			expired = append(expired, p)
			continue
		} else if p.deadline.Before(t) {
			expired = append(expired, p)
		}
	}
	return expired
}

// implement sort.Interface
func (seq inflightSequence) Len() int {
	return len(seq)
}

// implement sort.Interface
func (seq inflightSequence) Swap(i, j int) {
	seq[i], seq[j] = seq[j], seq[i]
}

// implement sort.Interface
func (seq inflightSequence) Less(i, j int) bool {
	return seq[i].packet.ID < seq[j].packet.ID
}

// A incomingSequence is an array of sequentialPackets. It's used to store both incoming and outgoing packet queues.
// a incomingSequence can be sorted.
type incomingSequence []sequentialPacket

// implement sort.Interface
func (ps incomingSequence) Len() int {
	return len(ps)
}

// implement sort.Interface
func (ps incomingSequence) Swap(i, j int) {
	ps[i], ps[j] = ps[j], ps[i]
}

// implement sort.Interface
func (ps incomingSequence) Less(i, j int) bool {
	return ps[i].ID() < ps[j].ID()
}

type incomingPacket struct {
	packet *model.Packet
}

func (ip *incomingPacket) ID() model.PacketID {
	return ip.packet.ID
}

func (ip *incomingPacket) ExtractACKs() []model.PacketID {
	return ip.packet.ACKs
}

func (ip *incomingPacket) Packet() *model.Packet {
	return ip.packet
}

// incomingPacketSeen is a struct that the receiver sends us when a new packet is seen.
type incomingPacketSeen struct {
	id   optional.Value[model.PacketID]
	acks optional.Value[[]model.PacketID]
}
