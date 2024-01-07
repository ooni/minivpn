package datachannel

//
// OpenVPN data channel
//

import (

	//"github.com/ooni/minivpn/internal/datachannel"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
)

// Service is the datachannel service. Make sure you initialize
// the channels before invoking [Service.StartWorkers].
type Service struct {
	DataPacketUp chan *model.Packet
	KeyUp        chan *session.DataChannelKey
}

// StartWorkers starts the data-channel workers.
//
// We start three workers:
//
// 1. moveUpWorker BLOCKS on packetUpBottom to read a raw packet and
// eventually BLOCKS on packetUpTop to deliver it; this loop also
// BLOCKS on notifications to handle RESET messages;
//
// 2. moveDownWorker BLOCKS on packetDownTop to read a packet and
// eventually BLOCKS on packetDownBottom to deliver it;
//
// 3. keyWorker BLOCKS on keyUp to read an dataChannelKey and
// initializes the internal state with the resulting key;

func (s *Service) StartWorkers(
	logger model.Logger,
	workersManager *workers.Manager,
	sessionManager *session.Manager,
	options *model.Options,
) {
	dc, err := NewDataChannelFromOptions(logger, options, sessionManager)
	if err != nil {
		logger.Warnf("cannot initialize channel %v", err)
		return
	}
	ws := &workersState{
		logger:         logger,
		workersManager: workersManager,
		sessionManager: sessionManager,
		keyUp:          s.KeyUp,
		dataChannel:    dc,
	}
	workersManager.StartWorker(ws.moveUpWorker)
	workersManager.StartWorker(ws.moveDownWorker)
	workersManager.StartWorker(ws.keyWorker)
}

// workersState contains the data channel state.
type workersState struct {
	logger         model.Logger
	workersManager *workers.Manager
	sessionManager *session.Manager
	keyUp          <-chan *session.DataChannelKey
	dataChannel    *DataChannel
}

// moveUpWorker moves packets up the stack
func (ws *workersState) moveUpWorker() {
	defer func() {
		ws.workersManager.OnWorkerDone()
		ws.workersManager.StartShutdown()
		ws.logger.Debug("datachannel: moveUpWorker: done")
	}()
	select {}
}

// moveDownWorker moves packets up the stack
func (ws *workersState) moveDownWorker() {
	defer func() {
		ws.workersManager.OnWorkerDone()
		ws.workersManager.StartShutdown()
		ws.logger.Debug("datachannel: moveDownWorker: done")
	}()
	select {}
}

// keyWorker receives notifications from key ready
func (ws *workersState) keyWorker() {
	defer func() {
		ws.workersManager.OnWorkerDone()
		ws.workersManager.StartShutdown()
		ws.logger.Debug("datachannel: worker: done")
	}()

	ws.logger.Debug("datachannel: worker: started")
	for {
		select {
		case key := <-ws.keyUp:
			err := ws.dataChannel.setupKeys(key)
			if err != nil {
				ws.logger.Warnf("error on key derivation: %v", err)
			} else {
				ws.sessionManager.SetNegotiationState(session.S_GENERATED_KEYS)
			}

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}
