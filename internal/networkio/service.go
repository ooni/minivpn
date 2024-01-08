package networkio

import (
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/workers"
)

// Service is the network I/O service. Make sure you initialize
// the channels before invoking [Service.StartWorkers].
type Service struct {
	RawPacketDown chan []byte
	RawPacketUp   *chan []byte
}

// StartWorkers starts the network I/O workers. See the [ARCHITECTURE]
// file for more information about the network I/O workers.
//
// This function TAKES OWNERSHIP of the conn.
//
// [ARCHITECTURE]: https://github.com/ooni/minivpn/blob/main/ARCHITECTURE.md
func (svc *Service) StartWorkers(
	logger model.Logger,
	manager *workers.Manager,
	conn FramingConn,
) {
	ws := &workersState{
		conn:          conn,
		logger:        logger,
		manager:       manager,
		rawPacketDown: svc.RawPacketDown,
		rawPacketUp:   *svc.RawPacketUp,
	}
	manager.StartWorker(ws.moveUpWorker) // TAKES conn ownership
	manager.StartWorker(ws.moveDownWorker)
}

// workersState contains the service workers state
type workersState struct {
	// conn is the connection to use
	conn FramingConn

	// logger is the logger to use
	logger model.Logger

	// manager controls the workers lifecycle
	manager *workers.Manager

	// rawPacketDown is the channel for reading outgoing packets
	rawPacketDown <-chan []byte

	// rawPacketUp is the channel for writing incoming packets
	rawPacketUp chan<- []byte
}

// moveUpWorker moves packets up the stack.
func (ws *workersState) moveUpWorker() {
	defer func() {
		// make sure the manager knows we're done
		ws.manager.OnWorkerDone()

		// tear down everything else because a workers exited
		ws.manager.StartShutdown()

		// we OWN the connection
		ws.conn.Close()

		// emit useful debug message
		ws.logger.Debug("networkio: moveUpWorker: done")
	}()

	ws.logger.Debug("networkio: moveUpWorker: started")

	for {
		// POSSIBLY BLOCK on the connection to read a new packet
		pkt, err := ws.conn.ReadRawPacket()
		if err != nil {
			ws.logger.Infof("networkio: moveUpWorker: ReadRawPacket: %s", err.Error())
			return
		}

		// ws.logger.Infof("DEBUG < read %v bytes, select", len(pkt))

		// POSSIBLY BLOCK on the channel to deliver the packet
		select {
		case ws.rawPacketUp <- pkt:
			// ws.logger.Infof("< incoming %v bytes", len(pkt))
		case <-ws.manager.ShouldShutdown():
			return
		}
	}
}

// moveDownWorker moves packets down the stack
func (ws *workersState) moveDownWorker() {
	defer func() {
		ws.manager.StartShutdown()
		ws.manager.OnWorkerDone()
		ws.conn.Close()
		ws.logger.Debug("networkio: moveDownWorker: done")
	}()

	ws.logger.Debug("networkio: moveDownWorker: started")

	for {
		// While this channel receive could possibly block, the [ARCHITECTURE] is
		// such that (1) the channel is buffered and (2) the channel sender should
		// avoid blocking when inserting data into the channel.
		//
		// [ARCHITECTURE]: https://github.com/ooni/minivpn/blob/main/ARCHITECTURE.md
		select {
		case pkt := <-ws.rawPacketDown:
			// POSSIBLY BLOCK on the connection to write the packet
			if err := ws.conn.WriteRawPacket(pkt); err != nil {
				ws.logger.Infof("networkio: moveDownWorker: WriteRawPacket: %s", err.Error())
				return
			}

		case <-ws.manager.ShouldShutdown():
			return
		}
	}
}
