package reliabletransport

import (
	"fmt"
	"sort"
	"time"

	"github.com/ooni/minivpn/internal/model"
)

// moveDownWorker moves packets down the stack (sender)
// The sender and receiver data structures lack mutexes because they are
// intended to be confined to a single goroutine (one for each worker), and
// they SHOULD ONLY communicate via message passing.
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

			// try to insert and schedule for immediate wakeup
			if inserted := sender.TryInsertOutgoingPacket(packet); inserted {
				ticker.Reset(time.Nanosecond)
			}

		case seenPacket := <-sender.incomingSeen:
			// possibly evict any acked packet (in the ack array)
			// and add any id to the queue of packets to ack
			sender.OnIncomingPacketSeen(seenPacket)

			if len(sender.pendingACKsToSend) == 0 {
				continue
			}

			// reschedule the ticker
			if len(sender.pendingACKsToSend) >= 2 {
				ticker.Reset(time.Nanosecond)
				continue
			}

			// if there's no event soon, give some time for other acks to arrive
			// TODO: review if we need this optimization.
			// TODO: maybe only during TLS handshake??
			now := time.Now()
			timeout := inflightSequence(sender.inFlight).nearestDeadlineTo(now)
			gracePeriod := time.Millisecond * 20
			if timeout.Sub(now) > gracePeriod {
				fmt.Println(">> next wakeup too late, schedule in", gracePeriod)
				ticker.Reset(gracePeriod)
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

			ticker.Reset(timeout.Sub(now))

			scheduledNow := inflightSequence(sender.inFlight).readyToSend(now)

			if len(scheduledNow) > 0 {
				// we flush everything that is ready to be sent.
				for _, p := range scheduledNow {
					p.ScheduleForRetransmission(now)

					// append any pending ACKs
					p.packet.ACKs = sender.NextPacketIDsToACK()

					p.packet.Log(ws.logger, model.DirectionOutgoing)
					select {
					case ws.dataOrControlToMuxer <- p.packet:
					case <-ws.workersManager.ShouldShutdown():
						return
					}
				}
			} else {
				// there's nothing ready to be sent, so we see if we've got pending ACKs
				if len(sender.pendingACKsToSend) == 0 {
					continue
				}
				// special case, we want to send the clientHello as soon as possible
				// (TODO: coordinate this with hardReset)
				if len(sender.pendingACKsToSend) == 1 && sender.pendingACKsToSend[0] == model.PacketID(0) {
					continue
				}

				fmt.Println(":: CREATING ACK", len(sender.pendingACKsToSend), "pending to ack")

				ACK, err := ws.sessionManager.NewACKForPacketIDs(sender.NextPacketIDsToACK())
				if err != nil {
					ws.logger.Warnf("%s: cannot create ack: %v", workerName, err.Error())
				}
				ACK.Log(ws.logger, model.DirectionOutgoing)
				select {
				case ws.dataOrControlToMuxer <- ACK:
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

func (r *reliableSender) OnIncomingPacketSeen(seen incomingPacketSeen) {
	// we have received an incomingPacketSeen on the shared channel, we need to do two things:

	// 1. add the ID to the queue of packets to be acknowledged.
	if !seen.id.IsNone() {
		// TODO: do it only if not already in the array
		// FIXME --------------------------------------
		r.pendingACKsToSend = append(r.pendingACKsToSend, seen.id.Unwrap())
	}

	// 2. for every ACK received, see if we need to evict or bump the in-flight packet.
	if !seen.acks.IsNone() {
		for _, packetID := range seen.acks.Unwrap() {
			r.MaybeEvictOrBumpPacketAfterACK(packetID)
		}
	}
}

var _ outgoingPacketHandler = &reliableSender{}
