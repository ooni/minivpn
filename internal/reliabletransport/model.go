package reliabletransport

import (
	"github.com/ooni/minivpn/internal/model"
)

// sequentialPacket is a packet that can return a [model.PacketID].
type sequentialPacket interface {
	ID() model.PacketID
	ExtractACKs() []model.PacketID
	Packet() *model.Packet
}

// retransmissionPacket is a packet that can be scheduled for retransmission.
type retransmissionPacket interface {
	ScheduleForRetransmission()
}

type outgoingPacketWriter interface {
	// TryInsertOutgoingPacket attempts to insert a packet into the
	// inflight queue. If return value is false, insertion was not successful (e.g., too many
	// packets in flight).
	TryInsertOutgoingPacket(*model.Packet) bool
}

type seenPacketHandler interface {
	// OnIncomingPacketSeen processes a notification received in the shared lateral channel where receiver
	// notifies sender of incoming packets. There are two side-effects expected from this call:
	// 1. The ID in incomingPacketSeen needs to be appended to the array of packets pending to be acked, if not already
	// there. This insertion needs to be reflected by NextPacketIDsToACK()
	// 2. Any ACK values in the incomingPacketSeen need to:
	//    a) evict the matching packet, if existing in the in flight queue, and
	//    b) increment the counter of acks-with-higher-pid for each packet with a lesser
	//       packet id (used for fast retransmission)
	OnIncomingPacketSeen(incomingPacketSeen)
}

type outgoingPacketHandler interface {
	// NextPacketIDsToACK returns an array of pending IDs to ACK to
	// our remote. The length of this array MUST NOT be larger than CONTROL_SEND_ACK_MAX.
	// This is used to append it to the ACK array of the outgoing packet.
	NextPacketIDsToACK() []model.PacketID
}

// incomingPacketHandler knows how to deal with incoming packets (going up).
type incomingPacketHandler interface {
	// MaybeInsertIncoming will insert a given packet in the reliable
	// incoming queue if it passes a series of sanity checks.
	MaybeInsertIncoming(*model.Packet) bool

	// NextIncomingSequence gets the largest sequence of packets ready to be passed along
	// to the control channel above us.
	NextIncomingSequence() incomingSequence
}
