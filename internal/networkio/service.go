package networkio

import (
	"fmt"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/workers"
)

var (
	serviceName = "networkio"
)

// Service is the network I/O service. Make sure you initialize
// the channels before invoking [Service.StartWorkers].
type Service struct {
	// MuxerToNetwork moves bytes down from the muxer to the network IO layer
	MuxerToNetwork chan []byte

	// NetworkToMuxer moves bytes up from the network IO layer to the muxer
	NetworkToMuxer *chan []byte
}

// StartWorkers starts the network I/O workers. See the [ARCHITECTURE]
// file for more information about the network I/O workers.
//
// [ARCHITECTURE]: https://github.com/ooni/minivpn/blob/main/ARCHITECTURE.md
func (svc *Service) StartWorkers(
	config *model.Config,
	manager *workers.Manager,
	conn FramingConn,
) {
	ws := &workersState{
		conn:           conn,
		logger:         config.Logger(),
		manager:        manager,
		muxerToNetwork: svc.MuxerToNetwork,
		networkToMuxer: *svc.NetworkToMuxer,
	}

	manager.StartWorker(ws.moveUpWorker)
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

	// muxerToNetwork is the channel for reading outgoing packets
	// that are coming down to us
	muxerToNetwork <-chan []byte

	// networkToMuxer is the channel for writing incoming packets
	// that are coming up to us from the net
	networkToMuxer chan<- []byte
}

// moveUpWorker moves packets up the stack.
func (ws *workersState) moveUpWorker() {
	workerName := fmt.Sprintf("%s: moveUpWorker", serviceName)

	defer func() {
		// make sure the manager knows we're done
		ws.manager.OnWorkerDone(workerName)

		// tear down everything else because a workers exited
		ws.manager.StartShutdown()
	}()

	ws.logger.Debug("networkio: moveUpWorker: started")

	for {
		// POSSIBLY BLOCK on the connection to read a new packet
		pkt, err := ws.conn.ReadRawPacket()
		if err != nil {
			ws.logger.Debugf("%s: ReadRawPacket: %s", workerName, err.Error())
			return
		}

		// POSSIBLY BLOCK on the channel to deliver the packet
		select {
		case ws.networkToMuxer <- pkt:
		case <-ws.manager.ShouldShutdown():
			return
		}
	}
}

// moveDownWorker moves packets down the stack
func (ws *workersState) moveDownWorker() {
	workerName := fmt.Sprintf("%s: moveDownWorker", serviceName)

	defer func() {
		// make sure the manager knows we're done
		ws.manager.OnWorkerDone(workerName)

		// tear down everything else because a worker exited
		ws.manager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)

	for {
		// POSSIBLY BLOCK when receiving from channel.
		select {
		case pkt := <-ws.muxerToNetwork:
			// POSSIBLY BLOCK on the connection to write the packet
			if err := ws.conn.WriteRawPacket(pkt); err != nil {
				ws.logger.Infof("%s: WriteRawPacket: %s", workerName, err.Error())
				return
			}

		case <-ws.manager.ShouldShutdown():
			return
		}
	}
}
