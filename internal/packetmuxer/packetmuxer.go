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
	ControlPacketUp *chan *model.Packet
	DataPacketUp    *chan *model.Packet
	HardReset       chan any
	PacketDown      chan *model.Packet
	RawPacketDown   *chan []byte
	RawPacketUp     chan []byte
}

// StartWorkers starts the packet-muxer workers. See the [ARCHITECTURE]
// file for more information about the packet-muxer workers.
//
// [ARCHITECTURE]: https://github.com/ooni/minivpn/blob/main/ARCHITECTURE.md
func (svc *Service) StartWorkers(
	logger model.Logger,
	workersManager *workers.Manager,
	sessionManager *session.Manager,
) {
	ws := &workersState{
		logger:          logger,
		controlPacketUp: *svc.ControlPacketUp,
		dataPacketUp:    *svc.DataPacketUp,
		hardReset:       svc.HardReset,
		packetDown:      svc.PacketDown,
		rawPacketDown:   *svc.RawPacketDown,
		rawPacketUp:     svc.RawPacketUp,
		sessionManager:  sessionManager,
		workersManager:  workersManager,
	}
	workersManager.StartWorker(ws.moveUpWorker)
	workersManager.StartWorker(ws.moveDownWorker)
}

// workersState contains the reliable transport workers state.
type workersState struct {
	// logger is the logger to use
	logger model.Logger

	// controlPacketUp is the channel for writing control packets going up the stack.
	controlPacketUp chan<- *model.Packet

	// dataPacketUp is the channel for writing data packets going up the stack.
	dataPacketUp chan<- *model.Packet

	// hardReset is the channel posted to force a hard reset.
	hardReset <-chan any

	// packetDown is the channel for reading all the packets traveling down the stack.
	packetDown <-chan *model.Packet

	// rawPacketDown is the channel for writing raw packets going down the stack.
	rawPacketDown chan<- []byte

	// rawPacketUp is the channel for reading raw packets going up the stack.
	rawPacketUp <-chan []byte

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
		case rawPacket := <-ws.rawPacketUp:
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
		case packet := <-ws.packetDown:

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
			case ws.rawPacketDown <- rawPacket:
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
	// create a CONTROL_HARD_RESET_CLIENT_V2 packet
	packet := ws.sessionManager.NewPacket(model.P_CONTROL_HARD_RESET_CLIENT_V2, nil)
	rawPacket, err := packet.Bytes()
	if err != nil {
		ws.logger.Warnf("packetmuxer: NewPacket: %s", err.Error())
		return err
	}

	// pass the packet to the lower layer
	select {
	case ws.rawPacketDown <- rawPacket:
		// nothing

	case <-ws.workersManager.ShouldShutdown():
		return workers.ErrShutdown
	}

	ws.logger.Info("> P_CONTROL_HARD_RESET_CLIENT_V2")

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
		return err
	}

	ws.logger.Infof("< %s", packet.Opcode)

	// handle the case where we're performing a HARD_RESET
	if ws.sessionManager.NegotiationState() == session.S_PRE_START &&
		packet.Opcode == model.P_CONTROL_HARD_RESET_SERVER_V2 {
		// XXX we need to implement
		return nil
	}

	// TODO: introduce other sanity checks here

	// multiplex the incoming packet POSSIBLY BLOCKING on delivering it
	if packet.IsControl() || packet.Opcode == model.P_ACK_V1 {
		select {
		case ws.controlPacketUp <- packet:
		case <-ws.workersManager.ShouldShutdown():
			return workers.ErrShutdown
		}
	} else {
		select {
		case ws.dataPacketUp <- packet:
		case <-ws.workersManager.ShouldShutdown():
			return workers.ErrShutdown
		}
	}

	return nil
}

// finishThreeWayHandshake responsds to the HARD_RESET_SERVER and finishes the handshake.
func (ws *workersState) finishThreeWayHandshake(packet *model.Packet) {
	// register the server's session (note: the PoV is the one of the server)
	ws.sessionManager.SetRemoteSessionID(packet.LocalSessionID)

	// we need to manually ACK because the reliable layer is above us
	ws.logger.Info("< P_CONTROL_HARD_RESET_SERVER_V2")

}
