package reliabletransport

import (
	"fmt"
	"sort"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/optional"
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

			if sender.pendingACKsToSend.Len() == 0 {
				continue
			}

			if sender.pendingACKsToSend.Len() >= 2 {
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
				// TODO --- mve this to function -------------------------------------------
				// TODO: somethingToACK(state) ---------------------------------------------
				// there's nothing ready to be sent, so we see if we've got pending ACKs
				if sender.pendingACKsToSend.Len() == 0 {
					continue
				}
				// special case, we want to send the clientHello as soon as possible -----------------------------
				// (TODO: coordinate this with hardReset)
				if sender.pendingACKsToSend.Len() == 1 && *sender.pendingACKsToSend.first() == model.PacketID(0) {
					continue
				}

				ws.logger.Debugf("Creating ACK: %d pending to ack", sender.pendingACKsToSend.Len())

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

// reliableSender keeps state about the in flight packet queue, and implements outgoingPacketHandler.
// Please use the constructor `newReliableSender()`
type reliableSender struct {

	// incomingSeen is a channel where we receive notifications for incoming packets seen by the receiver.
	incomingSeen <-chan incomingPacketSeen

	// inFlight is the array of in-flight packets.
	inFlight []*inFlightPacket

	// logger is the logger to use
	logger model.Logger

	// pendingACKsToSend is a set of packets that we still need to ACK.
	pendingACKsToSend *ackSet
}

// newReliableSender returns a new instance of reliableOutgoing.
func newReliableSender(logger model.Logger, i chan incomingPacketSeen) *reliableSender {
	return &reliableSender{
		incomingSeen:      i,
		inFlight:          make([]*inFlightPacket, 0, RELIABLE_SEND_BUFFER_SIZE),
		logger:            logger,
		pendingACKsToSend: newACKSet(),
	}
}

// implement outgoingPacketWriter
func (r *reliableSender) TryInsertOutgoingPacket(p *model.Packet) bool {
	if len(r.inFlight) >= RELIABLE_SEND_BUFFER_SIZE {
		r.logger.Warn("outgoing array full, dropping packet")
		return false
	}
	new := newInFlightPacket(p)
	r.inFlight = append(r.inFlight, new)
	return true
}

// OnIncomingPacketSeen implements seenPacketHandler
func (r *reliableSender) OnIncomingPacketSeen(seen incomingPacketSeen) {
	// we have received an incomingPacketSeen on the shared channel, we need to do two things:

	// 1. add the ID to the set of packets to be acknowledged.
	r.pendingACKsToSend.maybeAdd(seen.id)

	// 2. for every ACK received, see if we need to evict or bump the in-flight packet.
	if seen.acks.IsNone() {
		return
	}
	for _, packetID := range seen.acks.Unwrap() {
		r.maybeEvictOrMarkWithHigherACK(packetID)
	}
}

// maybeEvictOrMarkWithHigherACK iterates over all the in-flight packets. For each one,
// either evicts it (if the PacketID matches), or bumps the internal withHigherACK count in the
// packet (if the PacketID from the ACK is higher than the packet in the queue).
func (r *reliableSender) maybeEvictOrMarkWithHigherACK(acked model.PacketID) bool {
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

			// since the in-flight array is always sorted by ascending packet-id
			// (because of sequentiality assumption in the control channel),
			// we're done here.
			return true
		}
	}
	return false
}

// NextPacketIDsToACK implement outgoingPacketHandler
func (r *reliableSender) NextPacketIDsToACK() []model.PacketID {
	return r.pendingACKsToSend.nextToACK()
}

var _ outgoingPacketHandler = &reliableSender{}

// ackSet is a set of acks. The zero value struct
// is invalid, please use newACKSet.
type ackSet struct {
	// m is the map we use to represent the set.
	m map[model.PacketID]bool
}

// NewACKSet creates a new empty ACK set.
func newACKSet(ids ...model.PacketID) *ackSet {
	m := make(map[model.PacketID]bool)
	for _, id := range ids {
		m[id] = true
	}
	return &ackSet{m}
}

// maybeAdd unwraps the optional value, and if not empty it MUTATES the set to add a (possibly-new)
// packet ID to the set and. It returns the same set to the caller.
func (as *ackSet) maybeAdd(id optional.Value[model.PacketID]) *ackSet {
	if len(as.m) >= ACK_SET_CAPACITY {
		return as
	}
	if !id.IsNone() {
		as.m[id.Unwrap()] = true
	}
	return as
}

// nextToACK returns up to MAX_ACKS_PER_OUTGOING_PACKET from the set, sorted by ascending packet ID.
func (as *ackSet) nextToACK() []model.PacketID {
	ids := as.sorted()
	var next []model.PacketID
	if len(ids) <= MAX_ACKS_PER_OUTGOING_PACKET {
		next = ids
	} else {
		next = ids[:MAX_ACKS_PER_OUTGOING_PACKET]
	}
	for _, i := range next {
		delete(as.m, i)
	}
	return next
}

// first returns the first packetID in the set, in ascending order.
func (as *ackSet) first() *model.PacketID {
	ids := as.sorted()
	if len(ids) == 0 {
		return nil
	}
	return &ids[0]
}

// sorted returns a []model.PacketID array with the stored ids, in ascending order.
func (as *ackSet) sorted() []model.PacketID {
	ids := make([]model.PacketID, 0)
	for id := range as.m {
		ids = append(ids, id)
	}
	sort.SliceStable(ids, func(i, j int) bool {
		return ids[i] < ids[j]
	})
	return ids
}

func (as *ackSet) Len() int {
	return len(as.m)
}
