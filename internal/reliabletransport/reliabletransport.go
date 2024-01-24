// Package reliabletransport implements the reliable transport.
package reliabletransport

import (
	"bytes"
	"fmt"

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

// moveUpWorker moves packets up the stack
func (ws *workersState) moveUpWorker() {
	workerName := fmt.Sprintf("%s: moveUpWorker", serviceName)

	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)

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
			if err := ws.maybeACK(packet); err != nil {
				ws.logger.Warnf("%s: cannot ACK packet: %s", workerName, err.Error())
				continue
			}

			// TODO: here we should track ACKs

			// POSSIBLY BLOCK delivering to the upper layer
			select {
			case ws.reliableToControl <- packet:
			case <-ws.workersManager.ShouldShutdown():
				return
			}

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}

// moveDownWorker moves packets down the stack
func (ws *workersState) moveDownWorker() {
	workerName := fmt.Sprintf("%s: moveDownWorker", serviceName)

	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)

	// TODO: we should have timer for retransmission
	for {
		// POSSIBLY BLOCK reading the next packet we should move down the stack
		select {
		case packet := <-ws.controlToReliable:
			// TODO: here we should treat control packets specially

			ws.logger.Infof(
				"> %s localID=%x remoteID=%x [%d bytes]",
				packet.Opcode,
				packet.LocalSessionID,
				packet.RemoteSessionID,
				len(packet.Payload),
			)

			// POSSIBLY BLOCK delivering this packet to the lower layer
			select {
			case ws.dataOrControlToMuxer <- packet:
			case <-ws.workersManager.ShouldShutdown():
				return
			}

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}

// maybeACK sends an ACK when needed.
func (ws *workersState) maybeACK(packet *model.Packet) error {
	// currently we are ACKing every packet
	// TODO: implement better ACKing strategy

	// this function will fail if we don't know the remote session ID
	ACK, err := ws.sessionManager.NewACKForPacket(packet)
	if err != nil {
		return err
	}

	// move the packet down. CAN BLOCK writing to the shared channel to muxer.
	select {
	case ws.dataOrControlToMuxer <- ACK:
		return nil
	case <-ws.workersManager.ShouldShutdown():
		return workers.ErrShutdown
	}
}
