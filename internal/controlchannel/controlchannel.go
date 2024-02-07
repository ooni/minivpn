package controlchannel

import (
	"fmt"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
)

var (
	serviceName = "controlchannel"
)

// Service is the controlchannel service. Make sure you initialize
// the channels before invoking [Service.StartWorkers].
type Service struct {
	// NotifyTLS is the channel that sends notifications up to the TLS layer.
	NotifyTLS *chan *model.Notification

	// ControlToReliable moves packets from us down to the reliable layer.
	ControlToReliable *chan *model.Packet

	// ReliableToControl moves packets up to us from the reliable layer below.
	ReliableToControl chan *model.Packet

	// TLSRecordToControl moves bytes down to us from the TLS layer above.
	TLSRecordToControl chan []byte

	// TLSRecordFromControl moves bytes from us up to the TLS layer above.
	TLSRecordFromControl *chan []byte
}

// StartWorkers starts the control-channel workers. See the [ARCHITECTURE]
// file for more information about the packet-muxer workers.
//
// [ARCHITECTURE]: https://github.com/ooni/minivpn/blob/main/ARCHITECTURE.md
func (svc *Service) StartWorkers(
	config *model.Config,
	workersManager *workers.Manager,
	sessionManager *session.Manager,
) {
	ws := &workersState{
		logger:               config.Logger(),
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
	workerName := fmt.Sprintf("%s: moveUpWorker", serviceName)

	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)

	for {
		// POSSIBLY BLOCK on reading the packet moving up the stack
		select {
		case packet := <-ws.reliableToControl:
			// route the packets depending on their opcode
			switch packet.Opcode {

			case model.P_CONTROL_SOFT_RESET_V1:
				// We cannot blindly accept SOFT_RESET requests. They only make sense
				// when we have generated keys. Note that a SOFT_RESET returns us to
				// the INITIAL state, therefore, we will not have concurrent resets in place,
				// even if after the first key generation we receive two SOFT_RESET requests
				// back to back.

				if ws.sessionManager.NegotiationState() < session.S_GENERATED_KEYS {
					continue
				}
				ws.sessionManager.SetNegotiationState(session.S_INITIAL)
				// TODO(ainghazal): revisit this step.
				// when we implement key rotation.  OpenVPN has
				// the concept of a "lame duck", i.e., the
				// retiring key that needs to be expired a fixed time after the new
				// one starts its lifetime, and this might be a good place to try
				// to retire the old key.

				// notify the TLS layer that it should initiate
				// a TLS handshake and, if successful, generate
				// new keys for the data channel
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
	workerName := fmt.Sprintf("%s: moveDownWorker", serviceName)

	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)

	for {
		// POSSIBLY BLOCK on reading the TLS record moving down the stack
		select {
		case record := <-ws.tlsRecordToControl:
			// transform the record into a control message
			packet, err := ws.sessionManager.NewPacket(model.P_CONTROL_V1, record)
			if err != nil {
				ws.logger.Warnf("%s: NewPacket: %s", workerName, err.Error())
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
