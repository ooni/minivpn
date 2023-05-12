package controlchannel

import (
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
)

// Service is the controlchannel service. Make sure you initialize
// the channels before invoking [Service.StartWorkers].
type Service struct {
	NotifyTLS     *chan *model.Notification
	PacketDown    *chan *model.Packet
	PacketUp      chan *model.Packet
	TLSRecordDown chan []byte
	TLSRecordUp   *chan []byte
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
		logger:         logger,
		notifyTLS:      *svc.NotifyTLS,
		packetDown:     *svc.PacketDown,
		packetUp:       svc.PacketUp,
		tlsRecordDown:  svc.TLSRecordDown,
		tlsRecordUp:    *svc.TLSRecordUp,
		sessionManager: sessionManager,
		workersManager: workersManager,
	}
	workersManager.StartWorker(ws.moveUpWorker)
	workersManager.StartWorker(ws.moveDownWorker)
}

// workersState contains the control channel state.
type workersState struct {
	logger         model.Logger
	notifyTLS      chan<- *model.Notification
	packetDown     chan<- *model.Packet
	packetUp       <-chan *model.Packet
	tlsRecordDown  <-chan []byte
	tlsRecordUp    chan<- []byte
	sessionManager *session.Manager
	workersManager *workers.Manager
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
		case packet := <-ws.packetUp:
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
				case ws.tlsRecordUp <- packet.Payload:
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
		case record := <-ws.tlsRecordDown:
			// transform the record into a control message
			packet, err := ws.sessionManager.NewPacket(model.P_CONTROL_V1, record)
			if err != nil {
				ws.logger.Warnf("controlchannel: NewPacket: %s", err.Error())
				return
			}

			// POSSIBLY BLOCK on sending the packet down the stack
			select {
			case ws.packetDown <- packet:
				// nothing

			case <-ws.workersManager.ShouldShutdown():
				return
			}

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}

// THIS BELONGS TO TLS: WE NEED TO APPLY THIS LATER
/*
// controlMessageHeader is the header prefixed to control messages
var controlMessageHeader = []byte{0x00, 0x00, 0x00, 0x00}

// tlsRecordToControlMessage converts a TLS record to a control message.
func tlsRecordToControlMessage(tlsRecord []byte) (out []byte) {
	out = append(out, controlMessageHeader...)
	out = append(out, tlsRecord...)
	return out
}

// ErrMissingHeader indicates that we're missing the four-byte all-zero header.
var ErrMissingHeader = errors.New("missing four-byte all-zero header")

// ErrInvalidHeader indicates that the header is not a sequence of four zeroed bytes.
var ErrInvalidHeader = errors.New("expected four-byte all-zero header")

// parseControlMessage parses a control message and returns the TLS record inside it.
func parseControlMessage(message []byte) ([]byte, error) {
	if len(message) < 4 {
		return nil, ErrMissingHeader
	}
	if !bytes.Equal(message[:4], controlMessageHeader) {
		return nil, ErrInvalidHeader
	}
	return message[4:], nil
}
*/
