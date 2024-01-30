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

// inFlightPacket is a packet that, additionally, can keep track of how many acks for a packet with a higher PID have been received.
type inFlighter interface {
	sequentialPacket
	ScheduleForRetransmission()
}

// outgoingPacketHandler has methods to deal with the outgoing packets (going down).
type outgoingPacketHandler interface {
	// TryInsertOutgoingPacket attempts to insert a packet into the
	// inflight queue. If return value is false, insertion was not successful (e.g., too many
	// packets in flight).
	TryInsertOutgoingPacket(*model.Packet) bool

	// MaybeEvictOrBumpPacketAfterACK removes a packet (that we received an ack for) from the in-flight packet queue.
	MaybeEvictOrBumpPacketAfterACK(id model.PacketID) bool

	// NextPacketIDsToACK returns an array of pending IDs to ACK to
	// our remote. The length of this array MUST NOT be larger than CONTROL_SEND_ACK_MAX.
	// This is used to append it to the ACK array of the outgoing packet.
	NextPacketIDsToACK() []model.PacketID

	// OnIncomingPacketSeen processes a notification received in the shared channel for incoming packets.
	OnIncomingPacketSeen(incomingPacketSeen)
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
