package reliabletransport

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/optional"
)

// moveUpWorker moves packets up the stack (receiver).
// The sender and receiver data structures lack mutexes because they are
// intended to be confined to a single goroutine (one for each worker), and
// the workers SHOULD ONLY communicate via message passing.
func (ws *workersState) moveUpWorker() {
	workerName := fmt.Sprintf("%s: moveUpWorker", serviceName)

	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)

	receiver := newReliableReceiver(ws.logger, ws.incomingSeen)

	for {
		// POSSIBLY BLOCK reading a packet to move up the stack
		// or POSSIBLY BLOCK waiting for notifications
		select {
		case packet := <-ws.muxerToReliable:
			ws.tracer.OnIncomingPacket(packet)

			if packet.Opcode != model.P_CONTROL_HARD_RESET_SERVER_V2 {
				// the hard reset has already been logged by the layer below
				// TODO: move logging here?
				packet.Log(ws.logger, model.DirectionIncoming)
			}

			// TODO: are we handling a HARD_RESET_V2 while we're doing a handshake?
			// I'm not sure that's a valid behavior for a server.
			// We should be able to deterministically test how this affects the state machine.

			// drop a packet that is not for our session
			if !bytes.Equal(packet.RemoteSessionID[:], ws.sessionManager.LocalSessionID()) {
				ws.logger.Warnf(
					"%s: packet with invalid RemoteSessionID: expected %x; got %x",
					workerName,
					ws.sessionManager.LocalSessionID(),
					packet.RemoteSessionID,
				)
				continue
			}

			seen := receiver.newIncomingPacketSeen(packet)
			ws.incomingSeen <- seen

			// TODO(ainghazal): drop a packet that is a replay (id <= lastConsumed, but != ACK...?)

			// we only want to insert control packets going to the tls layer
			if packet.Opcode != model.P_CONTROL_V1 {
				// TODO: add reason
				ws.tracer.OnDroppedPacket(model.DirectionIncoming, packet)
				continue
			}

			if inserted := receiver.MaybeInsertIncoming(packet); !inserted {
				// this packet was not inserted in the queue: we drop it
				// TODO: add reason
				ws.tracer.OnDroppedPacket(model.DirectionIncoming, packet)
				ws.logger.Debugf("Dropping packet: %v", packet.ID)
				continue
			}

			ready := receiver.NextIncomingSequence()
			for _, nextPacket := range ready {
				// POSSIBLY BLOCK delivering to the upper layer
				select {
				case ws.reliableToControl <- nextPacket:
				case <-ws.workersManager.ShouldShutdown():
					return
				}
			}

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}

//
// incomingPacketHandler implementation.
//

// reliableReceiver is the receiver part that sees incoming packets moving up the stack.
// Please use the constructor `newReliableReceiver()`
type reliableReceiver struct {
	// logger is the logger to use
	logger model.Logger

	// incomingPackets are packets to process (reorder) before they are passed to TLS layer.
	incomingPackets incomingSequence

	// incomingSeen is a channel where we send notifications for incoming packets seen by us.
	incomingSeen chan<- incomingPacketSeen

	// lastConsumed is the last [model.PacketID] that we have passed to the control layer above us.
	lastConsumed model.PacketID
}

func newReliableReceiver(logger model.Logger, ch chan incomingPacketSeen) *reliableReceiver {
	return &reliableReceiver{
		logger:          logger,
		incomingPackets: make([]*model.Packet, 0),
		incomingSeen:    ch,
		lastConsumed:    0,
	}
}

func (r *reliableReceiver) MaybeInsertIncoming(p *model.Packet) bool {
	// we drop if at capacity, by default double the size of the outgoing buffer
	if len(r.incomingPackets) >= RELIABLE_RECV_BUFFER_SIZE {
		r.logger.Warnf("dropping packet, buffer full with len %v", len(r.incomingPackets))
		return false
	}

	// insert this one in the queue to pass to TLS.
	r.incomingPackets = append(r.incomingPackets, p)
	return true
}

func (r *reliableReceiver) NextIncomingSequence() incomingSequence {
	last := r.lastConsumed
	ready := make([]*model.Packet, 0, RELIABLE_RECV_BUFFER_SIZE)

	// sort them so that we begin with lower model.PacketID
	sort.Sort(r.incomingPackets)
	var keep incomingSequence

	for i, p := range r.incomingPackets {
		if p.ID-last == 1 {
			ready = append(ready, p)
			last++
		} else if p.ID > last {
			// here we broke sequentiality, but we want
			// to drop anything that is below lastConsumed
			keep = append(keep, r.incomingPackets[i:]...)
			break
		}
	}
	r.lastConsumed = last
	r.incomingPackets = keep
	return ready
}

func (r *reliableReceiver) newIncomingPacketSeen(p *model.Packet) incomingPacketSeen {
	incomingPacket := incomingPacketSeen{}
	if p.Opcode == model.P_ACK_V1 {
		incomingPacket.acks = optional.Some(p.ACKs)
	} else {
		incomingPacket.id = optional.Some(p.ID)
		incomingPacket.acks = optional.Some(p.ACKs)
	}

	return incomingPacket
}

// assert that reliableReceiver implements incomingPacketHandler
var _ incomingPacketHandler = &reliableReceiver{}
