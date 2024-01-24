package reliabletransport

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/ooni/minivpn/internal/model"
)

// moveUpWorker moves packets up the stack (receiver)
func (ws *workersState) moveUpWorker() {
	workerName := fmt.Sprintf("%s: moveUpWorker", serviceName)

	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)

	receiver := newReliableReceiver(ws.logger, ws.incomingSeen)

	// TODO: do we need to have notifications from the control channel
	// to reset state or can we do this implicitly?

	for {
		// POSSIBLY BLOCK reading a packet to move up the stack
		// or POSSIBLY BLOCK waiting for notifications
		select {
		case packet := <-ws.muxerToReliable:
			ws.logger.Infof(
				"< %s localID=%x remoteID=%x [%d bytes]",
				packet.Opcode,
				packet.LocalSessionID,
				packet.RemoteSessionID,
				len(packet.Payload),
			)

			// drop a packet that is not for our session
			if !bytes.Equal(packet.LocalSessionID[:], ws.sessionManager.RemoteSessionID()) {
				ws.logger.Warnf(
					"%s: packet with invalid RemoteSessionID: expected %x; got %x",
					workerName,
					ws.sessionManager.LocalSessionID(),
					packet.RemoteSessionID,
				)
				continue
			}

			// possibly ACK the incoming packet
			// TODO: move this responsibility to the sender.
			/*
				if err := ws.maybeACK(packet); err != nil {
					ws.logger.Warnf("%s: cannot ACK packet: %s", workerName, err.Error())
					continue
				}
			*/

			if inserted := receiver.MaybeInsertIncoming(packet); !inserted {
				// this packet was not inserted in the queue: we drop it
				continue
			}

			// TODO: possibly refactor so that the writing to the channel happens here
			// the fact this channel write is hidden makes following this harder
			// receiver.NotifySeen(packet)
			seenPacket, shouldDrop := receiver.newIncomingPacketSeen(packet)
			switch shouldDrop {
			case true:
				receiver.logger.Warnf("got packet id %v, but last consumed is %v (dropping)\n", packet.ID, receiver.lastConsumed)
			case false:
				ws.incomingSeen <- seenPacket
			}

			ready := receiver.NextIncomingSequence()
			for _, nextPacket := range ready {
				// POSSIBLY BLOCK delivering to the upper layer
				select {
				case ws.reliableToControl <- nextPacket.Packet():
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

func newReliableReceiver(logger model.Logger, i chan incomingPacketSeen) *reliableReceiver {
	return &reliableReceiver{
		logger:          logger,
		incomingPackets: []sequentialPacket{},
		incomingSeen:    i,
		lastConsumed:    0,
	}
}

func (r *reliableReceiver) MaybeInsertIncoming(p *model.Packet) bool {
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

func (r *reliableReceiver) NextIncomingSequence() incomingSequence {
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
	return ready
}

func (r *reliableReceiver) newIncomingPacketSeen(p *model.Packet) (incomingPacketSeen, bool) {
	shouldDrop := false
	incomingPacket := incomingPacketSeen{
		id:   p.ID,
		acks: p.ACKs,
	}
	r.logger.Debugf(
		"notify: <ID=%d acks=%v>",
		p.ID,
		p.ACKs,
	)
	if p.ID > 0 && p.ID <= r.lastConsumed {
		shouldDrop = true
	}
	return incomingPacket, shouldDrop
}

// assert that reliableIncoming implements incomingPacketHandler
var _ incomingPacketHandler = &reliableReceiver{
	logger:          nil,
	incomingPackets: []sequentialPacket{},
	incomingSeen:    make(chan<- incomingPacketSeen),
	lastConsumed:    0,
}
