package reliabletransport

import (
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/optional"
)

// inFlightPacket wraps a [model.Packet] with metadata for retransmission.
type inFlightPacket struct {
	// deadline is a moment in time when is this packet scheduled for the next retransmission.
	deadline time.Time

	// how many acks we've received for packets with higher PID.
	higherACKs int

	// packet is the underlying packet being sent.
	packet *model.Packet

	// retries is a monotonically increasing counter for retransmission.
	retries int
}

func newInFlightPacket(p *model.Packet) *inFlightPacket {
	return &inFlightPacket{
		deadline:   time.Time{},
		higherACKs: 0,
		packet:     p,
		retries:    0,
	}
}

// ACKForHigherPacket increments the number of acks received for a higher pid than this packet. This will influence the fast rexmit selection algorithm.
func (p *inFlightPacket) ACKForHigherPacket() {
	p.higherACKs++
}

func (p *inFlightPacket) ScheduleForRetransmission(t time.Time) {
	p.retries++
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

// inflightSequence is a sequence of inFlightPackets.
// A inflightSequence MUST be sorted (since the controlchannel has assigned sequential packet IDs when creating the
// packet)
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

// readyToSend returns the subset of this sequence that has a expired deadline or
// is suitable for fast retransmission.
func (seq inflightSequence) readyToSend(t time.Time) inflightSequence {
	expired := make([]*inFlightPacket, 0)
	for _, p := range seq {
		if p.higherACKs >= 3 {
			expired = append(expired, p)
			continue
		}
		if p.deadline.Before(t) {
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

// An incomingSequence is an array of [model.Packet].
// An incomingSequence can be sorted.
type incomingSequence []*model.Packet

// implement sort.Interface
func (seq incomingSequence) Len() int {
	return len(seq)
}

// implement sort.Interface
func (seq incomingSequence) Swap(i, j int) {
	seq[i], seq[j] = seq[j], seq[i]
}

// implement sort.Interface
func (seq incomingSequence) Less(i, j int) bool {
	return seq[i].ID < seq[j].ID
}

// incomingPacketSeen is a struct that the receiver sends us when a new packet is seen.
type incomingPacketSeen struct {
	id   optional.Value[model.PacketID]
	acks optional.Value[[]model.PacketID]
}
