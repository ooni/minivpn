package reliabletransport

import (
	"fmt"
	"sort"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/workers"
)

// moveDownWorker moves packets down the stack (sender)
// TODO move the worker to sender.go
func (ws *workersState) moveDownWorker() {
	workerName := fmt.Sprintf("%s: moveDownWorker", serviceName)

	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)

	sender := newReliableSender(ws.logger, ws.incomingSeen)
	ticker := time.NewTicker(time.Duration(SENDER_TICKER_MS) * time.Millisecond)

	for {
		// POSSIBLY BLOCK reading the next packet we should move down the stack
		select {
		case packet := <-ws.controlToReliable:
			ws.logger.Infof(
				"> %s localID=%x remoteID=%x [%d bytes]",
				packet.Opcode,
				packet.LocalSessionID,
				packet.RemoteSessionID,
				len(packet.Payload),
			)

			sender.TryInsertOutgoingPacket(packet)
			// schedule for inmediate wakeup
			// so that the ticker will wakeup and see if there's anything pending to be sent.
			ticker.Reset(time.Nanosecond)

		case seenPacket := <-sender.incomingSeen:
			// possibly evict any acked packet
			sender.OnIncomingPacketSeen(seenPacket)

			if seenPacket.id < sender.lastACKed {
				continue
			}

			now := time.Now()

			// this is quite arbitrary
			tooLate := now.Add(1000 * time.Millisecond)

			nextTimeout := inflightSequence(sender.inFlight).nearestDeadlineTo(now)

			if nextTimeout.After(tooLate) {
				// we don't want to wait so much, so we do send the ACK immediately.
				if err := ws.doSendACK(&model.Packet{ID: seenPacket.id}); err != nil {
					sender.lastACKed += 1
				}

				// TODO: ------------------------------------------------------------
				// discuss: how can we gauge the sending queue? should we peek what's
				// if len(ws.controlToReliable) != 0 {
			} else {
				// we'll be fine by having these ACKs hitching a ride on the next outgoing packet
				// that is scheduled to go soon anyways
				fmt.Println(">>> SHOULD SEND SOON ENOUGH, APPEND ACK!--------------")
				sender.pendingACKsToSend = append(sender.pendingACKsToSend, seenPacket.acks...)
				// TODO: not needed anymore.
				// and now we schedule for inmediate wakeup, because we probably need to update ACKs
				// ticker.Reset(time.Nanosecond)
			}

		case <-ticker.C:
			// First of all, we reset the ticker to the next timeout.
			// By default, that's going to return one minute if there are no packets
			// in the in-flight queue.

			// nearestDeadlineTo(now) ensures that we do not receive a time before now, and
			// that increments the passed moment by an epsilon if all deadlines are expired,
			// so it should be safe to reset the ticker with that timeout.
			now := time.Now()
			timeout := inflightSequence(sender.inFlight).nearestDeadlineTo(now)

			ws.logger.Debug("")
			ws.logger.Debugf("next wakeup: %v", timeout.Sub(now))

			ticker.Reset(timeout.Sub(now))

			// we flush everything that is ready to be sent.
			scheduledNow := inflightSequence(sender.inFlight).readyToSend(now)
			ws.logger.Debugf(":: GOT %d packets to send\n", len(scheduledNow))

			for _, p := range scheduledNow {
				p.ScheduleForRetransmission(now)
				// TODO -------------------------------------------
				// ideally, we want to append any pending ACKs here
				select {
				case ws.dataOrControlToMuxer <- p.packet:
					ws.logger.Debugf("==> sent packet with ID: %v", p.packet.ID)
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
// outgoingPacketHandler implementation.
//

// reliableSender keeps state about the outgoing packet queue, and implements outgoingPacketHandler.
// Please use the constructor `newReliableSender()`
type reliableSender struct {

	// incomingSeen is a channel where we receive notifications for incoming packets seen by the receiver.
	incomingSeen <-chan incomingPacketSeen

	// inFlight is the array of in-flight packets.
	inFlight []*inFlightPacket

	// lastACKed is the last packet ID from the remote that we have acked
	lastACKed model.PacketID

	// logger is the logger to use
	logger model.Logger

	// pendingACKsToSend is the array of packets that we still need to ACK.
	pendingACKsToSend []model.PacketID
}

// newReliableSender returns a new instance of reliableOutgoing.
func newReliableSender(logger model.Logger, i chan incomingPacketSeen) *reliableSender {
	return &reliableSender{
		incomingSeen:      i,
		inFlight:          make([]*inFlightPacket, 0, RELIABLE_SEND_BUFFER_SIZE),
		lastACKed:         model.PacketID(0),
		logger:            logger,
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

// doSendACK sends an ACK when needed.
func (ws *workersState) doSendACK(packet *model.Packet) error {
	// this function will fail if we don't know the remote session ID
	ACK, err := ws.sessionManager.NewACKForPacket(packet)
	if err != nil {
		return err
	}

	// move the packet down. CAN BLOCK writing to the shared channel to muxer.
	select {
	case ws.dataOrControlToMuxer <- ACK:
		ws.logger.Debugf("====> ack for remote packet id: %d", packet.ID)
		return nil
	case <-ws.workersManager.ShouldShutdown():
		return workers.ErrShutdown
	}
}
