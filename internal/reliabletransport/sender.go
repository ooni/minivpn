package reliabletransport

import (
	"sort"

	"github.com/ooni/minivpn/internal/model"
)

// reliableSender keeps state about the outgoing packet queue, and implements outgoingPacketHandler.
// Please use the constructor `newReliableSender()`
type reliableSender struct {
	// logger is the logger to use
	logger model.Logger

	// incomingSeen is a channel where we receive notifications for incoming packets seen by the receiver.
	incomingSeen <-chan incomingPacketSeen

	// inFlight is the array of in-flight packets.
	inFlight []*inFlightPacket

	// pendingACKsToSend is the array of packets that we still need to ACK.
	pendingACKsToSend []model.PacketID
}

// newReliableSender returns a new instance of reliableOutgoing.
func newReliableSender(logger model.Logger, i chan incomingPacketSeen) *reliableSender {
	return &reliableSender{
		logger:            logger,
		incomingSeen:      i,
		inFlight:          make([]*inFlightPacket, 0, RELIABLE_SEND_BUFFER_SIZE),
		pendingACKsToSend: []model.PacketID{},
	}
}

//
// outgoingPacketHandler implementation.
//

func (r *reliableSender) TryInsertOutgoingPacket(p *model.Packet) bool {
	if len(r.inFlight) >= RELIABLE_SEND_BUFFER_SIZE {
		r.logger.Warn("outgoing array full, dropping packet")
		return false
	}
	new := newInFlightPacket(p)
	r.inFlight = append(r.inFlight, new)
	return true
}

// MaybeEvictOrBumpPacketAfterACK iterates over all the in-flight packets. For each one,
// and either evicts it (if the PacketID matches), or bumps the internal withHigherACK count in the
// packet (if the PacketID from the ACK is higher than the packet in the queue).
func (r *reliableSender) MaybeEvictOrBumpPacketAfterACK(acked model.PacketID) bool {
	// TODO: it *should* be sorted, can it be not sorted?
	sort.Sort(inflightSequence(r.inFlight))

	packets := r.inFlight
	for i, p := range packets {
		if acked > p.packet.ID {
			// we have received an ACK for a packet with a higher pid, so let's bump it
			p.ACKForHigherPacket()

		} else if acked == p.packet.ID {

			// we have a match for the ack we just received: eviction it is!
			r.logger.Debugf("evicting packet %v", p.packet.ID)

			// first we swap this element with the last one:
			packets[i], packets[len(packets)-1] = packets[len(packets)-1], packets[i]

			// and now exclude the last element:
			r.inFlight = packets[:len(packets)-1]

			// since we had sorted the in-flight array, we're done here.
			return true
		}
	}
	return false
}

// this should return at most MAX_ACKS_PER_OUTGOING_PACKET packet IDs.
func (r *reliableSender) NextPacketIDsToACK() []model.PacketID {
	var next []model.PacketID
	if len(r.pendingACKsToSend) <= MAX_ACKS_PER_OUTGOING_PACKET {
		next = r.pendingACKsToSend[:len(r.pendingACKsToSend)]
		r.pendingACKsToSend = r.pendingACKsToSend[:0]
		return next
	}

	next = r.pendingACKsToSend[:MAX_ACKS_PER_OUTGOING_PACKET]
	r.pendingACKsToSend = r.pendingACKsToSend[MAX_ACKS_PER_OUTGOING_PACKET : len(r.pendingACKsToSend)-1]
	return next
}

func (r *reliableSender) OnIncomingPacketSeen(ips incomingPacketSeen) {
	// we have received an incomingPacketSeen on the shared channel, we need to do two things:

	// 1. add the ID to the queue of packets to be acknowledged.
	r.pendingACKsToSend = append(r.pendingACKsToSend, ips.id)

	// 2. for every ACK received, see if we need to evict or bump the in-flight packet.
	for _, packetID := range ips.acks {
		r.MaybeEvictOrBumpPacketAfterACK(packetID)
	}
}

var _ outgoingPacketHandler = &reliableSender{}
