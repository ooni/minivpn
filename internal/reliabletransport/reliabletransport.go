// Package reliabletransport implements the reliable transport.
package reliabletransport

import (
	"bytes"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
)

// Service is the reliable service. Make sure you initialize
// the channels before invoking [Service.StartWorkers].
type Service struct {
	PacketDownBottom *chan *model.Packet
	PacketDownTop    chan *model.Packet
	PacketUpBottom   chan *model.Packet
	PacketUpTop      *chan *model.Packet
}

// StartWorkers starts the reliable-transport workers. See the [ARCHITECTURE]
// file for more information about the reliable-transport workers.
//
// [ARCHITECTURE]: https://github.com/ooni/minivpn/blob/main/ARCHITECTURE.md
func (svc *Service) StartWorkers(
	logger model.Logger,
	workersManager *workers.Manager,
	sessionManager *session.Manager,
) {
	ws := &workersState{
		logger:           logger,
		packetDownBottom: *svc.PacketDownBottom,
		packetDownTop:    svc.PacketDownTop,
		packetUpBottom:   svc.PacketUpBottom,
		packetUpTop:      *svc.PacketUpTop,
		sessionManager:   sessionManager,
		workersManager:   workersManager,
	}
	workersManager.StartWorker(ws.moveUpWorker)
	workersManager.StartWorker(ws.moveDownWorker)
}

// workersState contains the reliable workers state
type workersState struct {
	// logger is the logger to use
	logger model.Logger

	// packetDownBottom is the channel where we write packets going down the stack.
	packetDownBottom chan<- *model.Packet

	// packetDownTop is the channel from which we read packets going down the stack.
	packetDownTop <-chan *model.Packet

	// packetUpBottom is the channel from which we read packets going up the stack.
	packetUpBottom <-chan *model.Packet

	// packetUpTop is the channel where we write packets going up the stack.
	packetUpTop chan<- *model.Packet

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
		ws.logger.Debug("reliable: moveUpWorker: done")
	}()

	ws.logger.Debug("reliable: moveUpWorker: started")

	// TODO: do we need to have notifications from the control channel
	// to reset state or can we do this implicitly?

	for {
		// POSSIBLY BLOCK reading a packet to move up the stack
		// or POSSIBLY BLOCK waiting for notifications
		select {
		case packet := <-ws.packetUpBottom:
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
					"reliable: moveUpWorker: packet with invalid RemoteSessionID: expected %x; got %x",
					ws.sessionManager.LocalSessionID(),
					packet.RemoteSessionID,
				)
				continue
			}

			// possibly ACK the incoming packet
			if err := ws.maybeACK(packet); err != nil {
				ws.logger.Warnf("reliable: moveUpWorker: cannot ACK packet: %s", err.Error())
				continue
			}

			// TODO: here we should track ACKs

			// POSSIBLY BLOCK delivering to the upper layer
			select {
			case ws.packetUpTop <- packet:
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
	defer func() {
		ws.workersManager.OnWorkerDone()
		ws.workersManager.StartShutdown()
		ws.logger.Debug("reliable: moveDownWorker: done")
	}()

	ws.logger.Debug("reliable: moveDownWorker: started")

	// TODO: we should have timer for retransmission
	for {
		// POSSIBLY BLOCK reading the next packet we should move down the stack
		select {
		case packet := <-ws.packetDownTop:
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
			case ws.packetDownBottom <- packet:
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

	// this function will fail if we won't know the remote session ID
	ACK, err := ws.sessionManager.NewACKForPacket(packet)
	if err != nil {
		return err
	}

	// move the packet down
	select {
	case ws.packetDownBottom <- ACK:
		return nil
	case <-ws.workersManager.ShouldShutdown():
		return workers.ErrShutdown
	}
}
