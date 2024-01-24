package reliabletransport

import (
	"sort"

	"github.com/ooni/minivpn/internal/model"
)

//
// incomingPacketHandler implementation.
//

// TODO rename to receiver
// reliableIncoming is the receiver part that sees incoming packets moving up the stack.
type reliableIncoming struct {
	// logger is the logger to use
	logger model.Logger

	// incomingPackets are packets to process (reorder) before they are passed to TLS layer.
	incomingPackets incomingSequence

	// incomingSeen is a channel where we send notifications for incoming packets seen by us.
	incomingSeen chan<- incomingPacketSeen

	// lastConsumed is the last [model.PacketID] that we have passed to the control layer above us.
	lastConsumed model.PacketID
}

func newReliableIncoming(logger model.Logger, i chan incomingPacketSeen) *reliableIncoming {
	return &reliableIncoming{
		logger:          logger,
		incomingPackets: []sequentialPacket{},
		incomingSeen:    i,
		lastConsumed:    0,
	}
}

// NotifySeen sends a incomingPacketSeen object to the shared channel where the sender will read it.
func (r *reliableIncoming) NotifySeen(p *model.Packet) bool {
	incoming := incomingPacketSeen{
		id:   p.ID,
		acks: p.ACKs,
	}
	if p.ID > 0 && p.ID <= r.lastConsumed {
		r.logger.Warnf("got packet id %v, but last consumed is %v\n", p.ID, r.lastConsumed)
	}
	r.incomingSeen <- incoming
	return true

}

func (r *reliableIncoming) MaybeInsertIncoming(p *model.Packet) bool {
	// we drop if at capacity, by default double the size of the outgoing buffer
	if len(r.incomingPackets) >= RELIABLE_RECV_BUFFER_SIZE {
		r.logger.Warnf("dropping packet, buffer full with len %v", len(r.incomingPackets))
		return false
	}

	inc := &incomingPacket{p}
	// insert this one in the queue to pass to TLS.
	r.incomingPackets = append(r.incomingPackets, inc)
	return true
}

func (r *reliableIncoming) NextIncomingSequence() incomingSequence {
	last := r.lastConsumed
	ready := make([]sequentialPacket, 0, RELIABLE_RECV_BUFFER_SIZE)

	// sort them so that we begin with lower model.PacketID
	sort.Sort(r.incomingPackets)
	keep := r.incomingPackets[:0]

	for i, p := range r.incomingPackets {
		if p.ID()-last == 1 {
			ready = append(ready, p)
			last += 1
		} else if p.ID() > last {
			// here we broke sequentiality, but we want
			// to drop anything that is below lastConsumed
			keep = append(keep, r.incomingPackets[i:]...)
			break
		}
	}
	r.lastConsumed = last
	r.incomingPackets = keep
	//if len(ready) != 0 {
	//r.logger.Debugf(">> BUMP LAST CONSUMED TO %v", last)
	//r.logger.Debugf(">> incoming now: %v", keep)
	//}
	return ready
}

// assert that reliableIncoming implements incomingPacketHandler
var _ incomingPacketHandler = &reliableIncoming{
	logger:          nil,
	incomingPackets: []sequentialPacket{},
	incomingSeen:    make(chan<- incomingPacketSeen),
	lastConsumed:    0,
}
