package datachannel

//
// OpenVPN data channel
//

import (
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
)

// Service is the datachannel service. Make sure you initialize
// the channels before invoking [Service.StartWorkers].
type Service struct {
	DataPacketUp   chan *model.Packet
	DataPacketDown *chan *model.Packet
	KeyUp          chan *session.DataChannelKey
	TunDown        chan []byte
	TunUp          chan []byte
}

// StartWorkers starts the data-channel workers.
//
// We start three workers:
//
// 1. moveUpWorker BLOCKS on dataPacketUp to read a packet coming from the muxer and
// eventually BLOCKS on tunUp to deliver it;
//
// 2. moveDownWorker BLOCKS on tunDown to read a packet and
// eventually BLOCKS on packetDown to deliver it;
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
		packetUp:       s.DataPacketUp,
		packetDown:     *s.DataPacketDown,
		tunUp:          s.TunUp,
		tunDown:        s.TunDown,
		dataChannel:    dc,
		newKey:         make(chan any),
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
	packetUp       <-chan *model.Packet
	packetDown     chan<- *model.Packet
	tunUp          chan<- []byte
	tunDown        <-chan []byte
	dataChannel    *DataChannel
	newKey         chan any
}

// moveDownWorker moves packets down the stack. It will BLOCK on PacketDown
func (ws *workersState) moveDownWorker() {
	defer func() {
		ws.workersManager.OnWorkerDone()
		ws.workersManager.StartShutdown()
		ws.logger.Debug("datachannel: moveDownWorker: done")
	}()
	for {
		select {
		// wait for the key to be ready
		case <-ws.newKey:
			for {
				select {
				case data := <-ws.tunDown:
					ws.logger.Infof("SHOULD ENCRYPT: %v", data)
					n, err := ws.dataChannel.writePacket(data)
					if err != nil {
						ws.logger.Warnf("error encrypting: %v", err)
						continue
					}
					ws.logger.Infof("encrypted %d bytes", n)
					// TODO: get packet ----
					// TODO: possibly block on write in packet down
					// ws.packetDown <- encrypted

				case <-ws.workersManager.ShouldShutdown():
					return
				}
			}
		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}

// moveUpWorker moves packets up the stack
func (ws *workersState) moveUpWorker() {
	defer func() {
		ws.workersManager.OnWorkerDone()
		ws.workersManager.StartShutdown()
		ws.logger.Debug("datachannel: moveUpWorker: done")
	}()
	for {
		select {
		case pkt := <-ws.packetUp:
			ws.logger.Infof("SHOULD DECRYPT: %v", pkt)

			// TODO: decrypt and write for tun
			decrypted, err := ws.dataChannel.readPacket(pkt)
			if err != nil {
				ws.logger.Warnf("error decrypting: %v", err)
			}
			ws.logger.Infof(">>> decrypted: %v", decrypted)
			// ws.tunUp <- decrypted
			// TODO possibly block on writing to upper
		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
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
				continue
			}
			ws.sessionManager.SetNegotiationState(session.S_GENERATED_KEYS)
			ws.newKey <- true

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}