// Package reliabletransport implements the reliable transport.
package reliabletransport

import (
	"bytes"
	"fmt"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
)

var (
	serviceName = "reliabletransport"
)

// Service is the reliable service. Make sure you initialize
// the channels before invoking [Service.StartWorkers].
type Service struct {
	// DataOrControlToMuxer is a shared channel that moves packets down to the muxer
	DataOrControlToMuxer *chan *model.Packet

	// ControlToReliable moves packets down to us
	ControlToReliable chan *model.Packet

	// MuxerToReliable moves packets up to us
	MuxerToReliable chan *model.Packet

	// ReliableToControl moves packets up from us to the control layer above
	ReliableToControl *chan *model.Packet
}

// StartWorkers starts the reliable-transport workers. See the [ARCHITECTURE]
// file for more information about the reliable-transport workers.
//
// [ARCHITECTURE]: https://github.com/ooni/minivpn/blob/main/ARCHITECTURE.md
func (s *Service) StartWorkers(
	logger model.Logger,
	workersManager *workers.Manager,
	sessionManager *session.Manager,
) {

	ws := &workersState{
		logger:               logger,
		incomingSeen:         make(chan incomingPacketSeen, 20),
		dataOrControlToMuxer: *s.DataOrControlToMuxer,
		controlToReliable:    s.ControlToReliable,
		muxerToReliable:      s.MuxerToReliable,
		reliableToControl:    *s.ReliableToControl,
		sessionManager:       sessionManager,
		workersManager:       workersManager,
	}
	workersManager.StartWorker(ws.moveUpWorker)
	workersManager.StartWorker(ws.moveDownWorker)
}

// workersState contains the reliable workers state
type workersState struct {
	// logger is the logger to use
	logger model.Logger

	// incomingSeen ins the shared channel to connect sender and receiver goroutines.
	incomingSeen chan incomingPacketSeen

	// dataOrControlToMuxer is the channel where we write packets going down the stack.
	dataOrControlToMuxer chan<- *model.Packet

	// controlToReliable is the channel from which we read packets going down the stack.
	controlToReliable <-chan *model.Packet

	// muxerToReliable is the channel from which we read packets going up the stack.
	muxerToReliable <-chan *model.Packet

	// reliableToControl is the channel where we write packets going up the stack.
	reliableToControl chan<- *model.Packet

	// sessionManager manages the OpenVPN session.
	sessionManager *session.Manager

	// workersManager controls the workers lifecycle.
	workersManager *workers.Manager
}

// moveUpWorker moves packets up the stack (receiver)
// TODO: move worker to receiver.go
func (ws *workersState) moveUpWorker() {
	workerName := fmt.Sprintf("%s: moveUpWorker", serviceName)

	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)

	receiver := newReliableIncoming(ws.logger, ws.incomingSeen)

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

			// TODO: drop a packet too far away (we can use lastConsumed)

			// possibly ACK the incoming packet
			// TODO: move this responsibility to the sender.
			if err := ws.maybeACK(packet); err != nil {
				ws.logger.Warnf("%s: cannot ACK packet: %s", workerName, err.Error())
				continue
			}

			ws.logger.Debugf(
				"notify: <ID=%d acks=%v>",
				packet.ID,
				packet.ACKs,
			)

			// TODO: possibly refactor so that the writing to the channel happens here
			// the fact this channel write is hidden makes following this harder
			// TODO: notify before dropping?
			receiver.NotifySeen(packet)

			if inserted := receiver.MaybeInsertIncoming(packet); !inserted {
				continue
			}

			// TODO drop first ------------------------------------------------
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

		case incomingSeen := <-sender.incomingSeen:
			// possibly evict any acked packet
			sender.OnIncomingPacketSeen(incomingSeen)

			// schedule for inmediate wakeup, because we probably need to update ACKs
			ticker.Reset(time.Nanosecond)

			// TODO need to ACK here if no packets pending.
			// I think we can just call withExpiredDeadline and ACK if len(expired) is 0

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

// maybeACK sends an ACK when needed.
func (ws *workersState) maybeACK(packet *model.Packet) error {
	// currently we are ACKing every packet
	// TODO: implement better ACKing strategy - this is basically moving the responsibility
	// to the sender, and then either appending up to 4 ACKs to the ACK array of an outgoing
	// packet, or sending a single ACK (if there's nothing pending to be sent).

	// this function will fail if we don't know the remote session ID
	ACK, err := ws.sessionManager.NewACKForPacket(packet)
	if err != nil {
		return err
	}

	// move the packet down. CAN BLOCK writing to the shared channel to muxer.
	select {
	case ws.dataOrControlToMuxer <- ACK:
		ws.logger.Debugf("ack for remote packet id: %d", packet.ID)
		return nil
	case <-ws.workersManager.ShouldShutdown():
		return workers.ErrShutdown
	}
}
