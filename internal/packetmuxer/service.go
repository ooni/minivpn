// Package packetmuxer implements the packet-muxer workers.
package packetmuxer

import (
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
)

// Service is the packetmuxer service. Make sure you initialize
// the channels before invoking [Service.StartWorkers].
type Service struct {
	HardReset       chan any
	NotifyTLS       *chan *model.Notification
	MuxerToReliable *chan *model.Packet
	MuxerToData     *chan *model.Packet
	// DataOrControlToMuxer moves packets down from reliable or from dataChannel
	DataOrControlToMuxer chan *model.Packet
	// MuxerToNetwork moves bytes down
	MuxerToNetwork *chan []byte
	// NetworkToMuxer moves bytes up
	NetworkToMuxer chan []byte
}

// StartWorkers starts the packet-muxer workers. See the [ARCHITECTURE]
// file for more information about the packet-muxer workers.
//
// [ARCHITECTURE]: https://github.com/ooni/minivpn/blob/main/ARCHITECTURE.md
func (s *Service) StartWorkers(
	logger model.Logger,
	workersManager *workers.Manager,
	sessionManager *session.Manager,
) {
	ws := &workersState{
		logger:               logger,
		hardReset:            s.HardReset,
		notifyTLS:            *s.NotifyTLS,
		muxerToReliable:      *s.MuxerToReliable,
		muxerToData:          *s.MuxerToData,
		dataOrControlToMuxer: s.DataOrControlToMuxer,
		muxerToNetwork:       *s.MuxerToNetwork,
		networkToMuxer:       s.NetworkToMuxer,
		sessionManager:       sessionManager,
		workersManager:       workersManager,
	}
	workersManager.StartWorker(ws.moveUpWorker)
	workersManager.StartWorker(ws.moveDownWorker)
}

// workersState contains the reliable transport workers state.
type workersState struct {
	// logger is the logger to use
	logger model.Logger

	// hardReset is the channel posted to force a hard reset.
	hardReset <-chan any

	// notifyTLS is used to send notifications to the TLS state service.
	notifyTLS chan<- *model.Notification

	// dataOrControlToMuxer is the channel for reading all the packets traveling down the stack.
	dataOrControlToMuxer <-chan *model.Packet

	// muxerToReliable is the channel for writing control packets going up the stack.
	muxerToReliable chan<- *model.Packet

	// muxerToData is the channel for writing data packets going up the stack.
	muxerToData chan<- *model.Packet

	// muxerToNetwork is the channel for writing raw packets going down the stack.
	muxerToNetwork chan<- []byte

	// networkToMuxer is the channel for reading raw packets going up the stack.
	networkToMuxer <-chan []byte

	// sessionManager manages the OpenVPN session.
	sessionManager *session.Manager

	// workersManager controls the workers lifecycle.
	workersManager *workers.Manager
}

// moveUpWorker moves packets up the stack
func (ws *workersState) moveUpWorker() {
	defer func() {
		ws.workersManager.OnWorkerDone()
		ws.workersManager.StartShutdown()
		ws.logger.Debug("packetmuxer: moveUpWorker: done")
	}()

	ws.logger.Debug("packetmuxer: moveUpWorker: started")

	for {
		// POSSIBLY BLOCK awaiting for incoming raw packet
		select {
		case rawPacket := <-ws.networkToMuxer:
			if err := ws.handleRawPacket(rawPacket); err != nil {
				// error already printed
				return
			}

		case <-ws.hardReset:
			if err := ws.startHardReset(); err != nil {
				// error already logged
				return
			}

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}

// moveDownWorker moves packets down the stack
func (ws *workersState) moveDownWorker() {
	defer func() {
		ws.workersManager.OnWorkerDone()
		ws.workersManager.StartShutdown()
		ws.logger.Debug("packetmuxer: moveDownWorker: done")
	}()

	ws.logger.Debug("packetmuxer: moveDownWorker: started")

	for {
		// POSSIBLY BLOCK on reading the packet moving down the stack
		select {
		case packet := <-ws.dataOrControlToMuxer:
			// serialize the packet
			rawPacket, err := packet.Bytes()
			if err != nil {
				ws.logger.Warnf("packetmuxer: cannot serialize packet: %s", err.Error())
				continue
			}

			// While this channel send could possibly block, the [ARCHITECTURE] is
			// such that (1) the channel is buffered and (2) the channel sender should
			// avoid blocking when inserting data into the channel.
			//
			// [ARCHITECTURE]: https://github.com/ooni/minivpn/blob/main/ARCHITECTURE.md
			select {
			case ws.muxerToNetwork <- rawPacket:
			default:
				// drop the packet if the buffer is full as documented above
			case <-ws.workersManager.ShouldShutdown():
				return
			}

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}

// startHardReset is invoked when we need to perform a HARD RESET.
func (ws *workersState) startHardReset() error {
	// emit a CONTROL_HARD_RESET_CLIENT_V2 pkt
	packet, err := ws.sessionManager.NewPacket(model.P_CONTROL_HARD_RESET_CLIENT_V2, nil)
	if err != nil {
		ws.logger.Warnf("packetmuxer: NewPacket: %s", err.Error())
		return err
	}
	if err := ws.serializeAndEmit(packet); err != nil {
		return err
	}

	// reset the state to become initial again
	ws.sessionManager.SetNegotiationState(session.S_PRE_START)

	// TODO: any other change to apply in this case?

	return nil
}

// handleRawPacket is the code invoked to handle a raw packet.
func (ws *workersState) handleRawPacket(rawPacket []byte) error {
	// make sense of the packet
	packet, err := model.ParsePacket(rawPacket)
	if err != nil {
		ws.logger.Warnf("packetmuxer: moveUpWorker: ParsePacket: %s", err.Error())
		return nil // keep running
	}

	// handle the case where we're performing a HARD_RESET
	if ws.sessionManager.NegotiationState() == session.S_PRE_START &&
		packet.Opcode == model.P_CONTROL_HARD_RESET_SERVER_V2 {
		return ws.finishThreeWayHandshake(packet)
	}

	// TODO: introduce other sanity checks here

	// multiplex the incoming packet POSSIBLY BLOCKING on delivering it
	if packet.IsControl() || packet.Opcode == model.P_ACK_V1 {
		select {
		case ws.muxerToReliable <- packet:
		case <-ws.workersManager.ShouldShutdown():
			return workers.ErrShutdown
		}
	} else {
		select {
		case ws.muxerToData <- packet:
		case <-ws.workersManager.ShouldShutdown():
			return workers.ErrShutdown
		}
	}

	return nil
}

// finishThreeWayHandshake responsds to the HARD_RESET_SERVER and finishes the handshake.
func (ws *workersState) finishThreeWayHandshake(packet *model.Packet) error {
	// register the server's session (note: the PoV is the server's one)
	ws.sessionManager.SetRemoteSessionID(packet.LocalSessionID)

	// we need to manually ACK because the reliable layer is above us
	ws.logger.Infof(
		"< %s localID=%x remoteID=%x [%d bytes]",
		packet.Opcode,
		packet.LocalSessionID,
		packet.RemoteSessionID,
		len(packet.Payload),
	)

	// create the ACK packet
	ACK, err := ws.sessionManager.NewACKForPacket(packet)
	if err != nil {
		return err
	}

	// emit the packet
	if err := ws.serializeAndEmit(ACK); err != nil {
		return err
	}

	// advance the state
	ws.sessionManager.SetNegotiationState(session.S_START)

	// attempt to tell TLS we want to handshake
	select {
	case ws.notifyTLS <- &model.Notification{Flags: model.NotificationReset}:
		// nothing

	default:
		// the architecture says this notification should be nonblocking

	case <-ws.workersManager.ShouldShutdown():
		return workers.ErrShutdown
	}

	return nil
}

// serializeAndEmit was written because Ain Ghazal was very insistent about it.
func (ws *workersState) serializeAndEmit(packet *model.Packet) error {
	// serialize it
	rawPacket, err := packet.Bytes()
	if err != nil {
		return err
	}

	// emit the packet
	select {
	case ws.muxerToNetwork <- rawPacket:
		// nothing

	case <-ws.workersManager.ShouldShutdown():
		return workers.ErrShutdown
	}

	ws.logger.Infof(
		"> %s localID=%x remoteID=%x [%d bytes]",
		packet.Opcode,
		packet.LocalSessionID,
		packet.RemoteSessionID,
		len(packet.Payload),
	)

	return nil
}
