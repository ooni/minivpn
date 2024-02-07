package reliabletransport

import (
	"fmt"
	"sort"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/optional"
)

var (
	// how long to wait for possible outgoing packets before sending a pending ACK as its own packet.
	//
	// We experimentally determined that this seems what OpenVPN does.
	gracePeriodForOutgoingACKs = time.Millisecond * 20
)

// moveDownWorker moves packets down the stack (sender).
// The sender and receiver data structures lack mutexes because they are
// intended to be confined to a single goroutine (one for each worker), and
// the workers SHOULD ONLY communicate via message passing.
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
			if shouldWakeup, when := sender.shouldWakeupAfterACK(time.Now()); shouldWakeup {
				ticker.Reset(when)
			}

		case <-ticker.C:
			ws.blockOnTryingToSend(sender, ticker)

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}

func (ws *workersState) blockOnTryingToSend(sender *reliableSender, ticker *time.Ticker) {
	// First of all, we reset the ticker to the next timeout.
	// By default, that's going to return one minute if there are no packets
	// in the in-flight queue.
	//
	// nearestDeadlineTo(now) ensures that we do not receive a time before now, and
	// that increments the passed moment by an epsilon if all deadlines are expired,
	// so it should be safe to reset the ticker with that timeout.
	now := time.Now()
	timeout := inflightSequence(sender.inFlight).nearestDeadlineTo(now)
	ticker.Reset(timeout.Sub(now))
	// figure out whether we need to send any packet here
	scheduledNow := inflightSequence(sender.inFlight).readyToSend(now)

	// if we have packets to send piggyback the ACKs
	if len(scheduledNow) > 0 {
		// we flush everything that is ready to be sent.
		for _, p := range scheduledNow {
			p.ScheduleForRetransmission(now)

			// append any pending ACKs
			p.packet.ACKs = sender.NextPacketIDsToACK()

			// log the packet
			p.packet.Log(ws.logger, model.DirectionOutgoing)
			ws.tracer.OnOutgoingPacket(p.packet, int(p.retries))

			select {
			case ws.dataOrControlToMuxer <- p.packet:
			case <-ws.workersManager.ShouldShutdown():
				return
			}
		}
		return
	}

	// if there are no ACKs to send, our job here is done
	if !sender.hasPendingACKs() {
		return
	}

	// All packets are inflight but we still owe ACKs to the peer.
	ws.logger.Debugf("Creating ACK: %d pending to ack", sender.pendingACKsToSend.Len())

	ACK, err := ws.sessionManager.NewACKForPacketIDs(sender.NextPacketIDsToACK())
	if err != nil {
		ws.logger.Warnf("moveDownWorker: tryToSend: cannot create ack: %v", err.Error())
		return
	}
	ACK.Log(ws.logger, model.DirectionOutgoing)
	select {
	case ws.dataOrControlToMuxer <- ACK:
	case <-ws.workersManager.ShouldShutdown():
		return
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
func newReliableSender(logger model.Logger, ch chan incomingPacketSeen) *reliableSender {
	return &reliableSender{
		incomingSeen:      ch,
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
	r.inFlight = append(r.inFlight, newInFlightPacket(p))
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
func (r *reliableSender) maybeEvictOrMarkWithHigherACK(acked model.PacketID) {
	pkts := r.inFlight
	for i, p := range pkts {
		if p.packet == nil {
			panic("malformed packet")
		}
		if acked > p.packet.ID {
			// we have received an ACK for a packet with a higher pid, so let's bump it
			p.ACKForHigherPacket()
		} else if acked == p.packet.ID {
			// we have a match for the ack we just received: eviction it is!
			r.logger.Debugf("evicting packet %v", p.packet.ID)

			// first we swap this element with the last one:
			pkts[i], pkts[len(pkts)-1] = pkts[len(pkts)-1], pkts[i]

			// and now exclude the last element:
			r.inFlight = pkts[:len(pkts)-1]
		}
	}
	sort.Sort(inflightSequence(r.inFlight))
}

// shouldRescheduleAfterACK checks whether we need to wakeup after receiving an ACK.
// TODO: change this depending on the handshake state --------------------------
func (r *reliableSender) shouldWakeupAfterACK(t time.Time) (bool, time.Duration) {
	if r.pendingACKsToSend.Len() <= 0 {
		return false, time.Minute
	}
	// for two or more ACKs pending, we want to send right now.
	if r.pendingACKsToSend.Len() >= 2 {
		return true, time.Nanosecond
	}
	// if we've got a single ACK to send, we give it a grace period in case no other packets are
	// scheduled to go out in this time.
	timeout := inflightSequence(r.inFlight).nearestDeadlineTo(t)

	if timeout.Sub(t) > gracePeriodForOutgoingACKs {
		r.logger.Debugf("next wakeup too late, schedule in %v", gracePeriodForOutgoingACKs)
		return true, gracePeriodForOutgoingACKs
	}
	return true, timeout.Sub(t)
}

// hasPendingACKs return true if there's any ack in the pending queue
func (r *reliableSender) hasPendingACKs() bool {
	return r.pendingACKsToSend.Len() != 0
}

// NextPacketIDsToACK implement outgoingPacketHandler
func (r *reliableSender) NextPacketIDsToACK() []model.PacketID {
	return r.pendingACKsToSend.nextToACK()
}

// assert reliableSender implements the needed interfaces

var _ outgoingPacketHandler = &reliableSender{}
var _ seenPacketHandler = &reliableSender{}
var _ outgoingPacketWriter = &reliableSender{}

// ackSet is a set of acks. The zero value struct is invalid, please use newACKSet.
type ackSet struct {
	// m is the map we use to represent the set.
	m map[model.PacketID]bool
}

// newACKSet creates a new empty ACK set.
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

// sorted returns a []model.PacketID array with the stored ids, in ascending order.
func (as *ackSet) sorted() []model.PacketID {
	ids := make([]model.PacketID, 0)
	if len(as.m) == 0 {
		return ids
	}
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
