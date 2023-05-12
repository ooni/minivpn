// Package reliable implements the reliable transport.
package reliable

import (
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/service"
	"github.com/ooni/minivpn/internal/session"
)

// FIXME: what kind of channel should the notification be like???? we
// should actually not have this notification

// StartWorkers starts the reliable-transport workers. See the [ARCHITECTURE]
// file for more information about the reliable-transport workers.
//
// [ARCHITECTURE]: https://github.com/ooni/minivpn/blob/main/ARCHITECTURE.md
func StartWorkers(
	logger model.Logger,
	serviceManager *service.Manager,
	sessionManager *session.Manager,
	notifications <-chan *model.Notification,
	packetDownBottom chan<- *model.Packet,
	packetDownTop <-chan *model.Packet,
	packetUpBottom <-chan *model.Packet,
	packetUpTop chan<- *model.Packet,
) {
	ws := &workersState{
		logger:           logger,
		notifications:    notifications,
		packetDownBottom: packetDownBottom,
		packetDownTop:    packetDownTop,
		packetUpBottom:   packetUpBottom,
		packetUpTop:      packetUpTop,
		serviceManager:   serviceManager,
		sessionManager:   sessionManager,
	}
	serviceManager.StartWorker(ws.moveUpWorker)
	serviceManager.StartWorker(ws.moveDownWorker)
}

// workersState contains the reliable service state
type workersState struct {
	// logger is the logger to use
	logger model.Logger

	// notifications is the channel from which we read notifications.
	notifications <-chan *model.Notification

	// packetDownBottom is the channel where we write packets going down the stack.
	packetDownBottom chan<- *model.Packet

	// packetDownTop is the channel from which we read packets going down the stack.
	packetDownTop <-chan *model.Packet

	// packetUpBottom is the channel from which we read packets going up the stack.
	packetUpBottom <-chan *model.Packet

	// packetUpTop is the channel where we write packets going up the stack.
	packetUpTop chan<- *model.Packet

	// serviceManager controls the workers lifecycle.
	serviceManager *service.Manager

	// sessionManager manages the OpenVPN session.
	sessionManager *session.Manager
}

// moveUpWorker moves packets up the stack
func (ws *workersState) moveUpWorker() {
	defer func() {
		ws.serviceManager.OnWorkerDone()
		ws.serviceManager.StartShutdown()
		ws.logger.Debug("reliable: moveUpLoop: done")
	}()

	ws.logger.Debug("reliable: moveUpLoop: started")

	for {
		// POSSIBLY BLOCK reading a packet to move up the stack
		// or POSSIBLY BLOCK waiting for notifications
		select {
		case packet := <-ws.packetUpBottom:
			// drop a packet that is not for our session
			if packet.RemoteSessionID != ws.sessionManager.LocalSessionID() {
				ws.logger.Warn("reliable: moveUpLoop: packet with invalid RemoteSessionID")
				continue
			}

			// possibly ACK the incoming packet
			if err := ws.maybeACK(packet); err != nil {
				ws.logger.Warnf("reliable: moveUpLoop: cannot ACK packet: %s", err.Error())
				continue
			}

			// TODO: here we should track ACKs

			// POSSIBLY BLOCK delivering to the upper layer
			select {
			case ws.packetUpTop <- packet:
			case <-ws.serviceManager.ShouldShutdown():
				return
			}

		case note := <-ws.notifications:
			if (note.Flags & model.NotificationReset) != 0 {
				// TODO: reset the reliable transport state
			}

		case <-ws.serviceManager.ShouldShutdown():
			return
		}
	}
}

// moveDownWorker moves packets down the stack
func (ws *workersState) moveDownWorker() {
	defer func() {
		ws.serviceManager.OnWorkerDone()
		ws.serviceManager.StartShutdown()
		ws.logger.Debug("reliable: moveDownLoop: done")
	}()

	ws.logger.Debug("reliable: moveDownLoop: started")

	// TODO: we should have timer for retransmission
	for {
		// POSSIBLY BLOCK reading the next packet we should move down the stack
		select {
		case packet := <-ws.packetDownTop:
			// TODO: here we should treat control packets specially

			// POSSIBLY BLOCK delivering this packet to the lower layer
			select {
			case ws.packetDownBottom <- packet:
			case <-ws.serviceManager.ShouldShutdown():
				return
			}

		case <-ws.serviceManager.ShouldShutdown():
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
	case <-ws.serviceManager.ShouldShutdown():
		return service.ErrShutdown
	}
}
