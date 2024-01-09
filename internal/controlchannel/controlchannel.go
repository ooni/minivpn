package controlchannel

import (
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
)

// Service is the controlchannel service. Make sure you initialize
// the channels before invoking [Service.StartWorkers].
type Service struct {
	NotifyTLS            *chan *model.Notification
	ControlToReliable    *chan *model.Packet
	ReliableToControl    chan *model.Packet
	TLSRecordToControl   chan []byte
	TLSRecordFromControl *chan []byte
}

// StartWorkers starts the control-channel workers. See the [ARCHITECTURE]
// file for more information about the packet-muxer workers.
//
// [ARCHITECTURE]: https://github.com/ooni/minivpn/blob/main/ARCHITECTURE.md
func (svc *Service) StartWorkers(
	logger model.Logger,
	workersManager *workers.Manager,
	sessionManager *session.Manager,
) {
	ws := &workersState{
		logger:               logger,
		notifyTLS:            *svc.NotifyTLS,
		controlToReliable:    *svc.ControlToReliable,
		reliableToControl:    svc.ReliableToControl,
		tlsRecordToControl:   svc.TLSRecordToControl,
		tlsRecordFromControl: *svc.TLSRecordFromControl,
		sessionManager:       sessionManager,
		workersManager:       workersManager,
	}
	workersManager.StartWorker(ws.moveUpWorker)
	workersManager.StartWorker(ws.moveDownWorker)
}

// workersState contains the control channel state.
type workersState struct {
	logger               model.Logger
	notifyTLS            chan<- *model.Notification
	controlToReliable    chan<- *model.Packet
	reliableToControl    <-chan *model.Packet
	tlsRecordToControl   <-chan []byte
	tlsRecordFromControl chan<- []byte
	sessionManager       *session.Manager
	workersManager       *workers.Manager
}

func (ws *workersState) moveUpWorker() {
	defer func() {
		ws.workersManager.OnWorkerDone()
		ws.workersManager.StartShutdown()
		ws.logger.Debug("controlchannel: moveUpWorker: done")
	}()

	ws.logger.Debug("controlchannel: moveUpWorker: started")

	for {
		// POSSIBLY BLOCK on reading the packet moving up the stack
		select {
		case packet := <-ws.reliableToControl:
			// route the packets depending on their opcode
			switch packet.Opcode {

			case model.P_CONTROL_SOFT_RESET_V1:
				// We cannot blindly accept SOFT_RESET requests. They only make sense
				// when we have generated keys. Note that a SOFT_RESET returns us to
				// the INITIAL state, therefore, we cannot have concurrent resets in place.
				if ws.sessionManager.NegotiationState() < session.S_GENERATED_KEYS {
					continue
				}
				ws.sessionManager.SetNegotiationState(session.S_INITIAL)

				// notify the TLS layer that it should TLS handshake and fetch
				// us new keys for the data channel
				select {
				case ws.notifyTLS <- &model.Notification{Flags: model.NotificationReset}:
					// nothing

				case <-ws.workersManager.ShouldShutdown():
					return
				}

			case model.P_CONTROL_V1:
				// send the packet to the TLS layer
				select {
				case ws.tlsRecordFromControl <- packet.Payload:
					// nothing

				case <-ws.workersManager.ShouldShutdown():
					return
				}
			}

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}

func (ws *workersState) moveDownWorker() {
	defer func() {
		ws.workersManager.OnWorkerDone()
		ws.workersManager.StartShutdown()
		ws.logger.Debug("controlchannel: moveUpWorker: done")
	}()

	ws.logger.Debug("controlchannel: moveUpWorker: started")

	for {
		// POSSIBLY BLOCK on reading the TLS record moving down the stack
		select {
		case record := <-ws.tlsRecordToControl:
			// transform the record into a control message
			packet, err := ws.sessionManager.NewPacket(model.P_CONTROL_V1, record)
			if err != nil {
				ws.logger.Warnf("controlchannel: NewPacket: %s", err.Error())
				return
			}

			// POSSIBLY BLOCK on sending the packet down the stack
			select {
			case ws.controlToReliable <- packet:
				// nothing

			case <-ws.workersManager.ShouldShutdown():
				return
			}

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}
