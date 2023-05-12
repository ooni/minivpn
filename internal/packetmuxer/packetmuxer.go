// Package packetmuxer implements the packet-muxer service.
package packetmuxer

import (
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/service"
	"github.com/ooni/minivpn/internal/session"
)

// StartWorkers starts the packet-muxer workers. See the [ARCHITECTURE]
// file for more information about the packet-muxer workers.
//
// [ARCHITECTURE]: https://github.com/ooni/minivpn/blob/main/ARCHITECTURE.md
func StartWorkers(
	logger model.Logger,
	serviceManager *service.Manager,
	sessionManager *session.Manager,
	controlPacketUp chan<- *model.Packet,
	dataPacketUp chan<- *model.Packet,
	packetDown <-chan *model.Packet,
	rawPacketDown chan<- []byte,
	rawPacketUp <-chan []byte,
) {
	ws := &workersState{
		logger:          logger,
		controlPacketUp: controlPacketUp,
		dataPacketUp:    dataPacketUp,
		packetDown:      packetDown,
		rawPacketDown:   rawPacketDown,
		rawPacketUp:     rawPacketUp,
		serviceManager:  serviceManager,
		sessionManager:  sessionManager,
	}
	serviceManager.StartWorker(ws.moveUpWorker)
	serviceManager.StartWorker(ws.moveDownWorker)
}

// workersState contains the reliable transport workers state.
type workersState struct {
	// logger is the logger to use
	logger model.Logger

	// controlPacketUp is the channel for writing control packets going up the stack.
	controlPacketUp chan<- *model.Packet

	// dataPacketUp is the channel for writing data packets going up the stack.
	dataPacketUp chan<- *model.Packet

	// packetDown is the channel for reading all the packets traveling down the stack.
	packetDown <-chan *model.Packet

	// rawPacketDown is the channel for writing raw packets going down the stack.
	rawPacketDown chan<- []byte

	// rawPacketUp is the channel for reading raw packets going up the stack.
	rawPacketUp <-chan []byte

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
		ws.logger.Debug("packetmuxer: moveUpLoop: done")
	}()

	ws.logger.Debug("packetmuxer: moveUpLoop: started")

	for {
		// POSSIBLY BLOCK awaiting for incoming raw packet
		select {
		case rawPacket := <-ws.rawPacketUp:
			// make sense of the packet
			packet, err := model.ParsePacket(rawPacket)
			if err != nil {
				ws.logger.Warnf("packetmuxer: moveUpLoop: ParsePacket: %s", err.Error())
				continue
			}

			// TODO: specially handle the case of the HARD_RESET and make
			// sure we notify the RELIABLE TRANSPORT about it

			// TODO: introduce other sanity checks here

			// multiplex the incoming packet POSSIBLY BLOCKING on delivering it
			if packet.IsControl() || packet.Opcode == model.P_ACK_V1 {
				select {
				case ws.controlPacketUp <- packet:
				case <-ws.serviceManager.ShouldShutdown():
					return
				}
			} else {
				select {
				case ws.dataPacketUp <- packet:
				case <-ws.serviceManager.ShouldShutdown():
					return
				}
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
		ws.logger.Debug("packetmuxer: moveDownLoop: done")
	}()

	ws.logger.Debug("packetmuxer: moveDownLoop: started")

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
			case <-ws.serviceManager.ShouldShutdown():
				return
			}

		case <-ws.serviceManager.ShouldShutdown():
			return
		}
	}
}
