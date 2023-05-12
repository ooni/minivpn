package controlchannel

import (
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/service"
	"github.com/ooni/minivpn/internal/session"
)

// StartWorkers starts the control-channel workers.
//
// We start two workers:
//
// 1. moveUpLoop BLOCKS on packetUpBottom to read a raw packet and
// eventually BLOCKS on packetUpTop to deliver it; this loop also
// BLOCKS on notifications to handle RESET messages;
//
// 2. moveDownLoop BLOCKS on packetDownTop to read a packet and
// eventually BLOCKS on packetDownBottom to deliver it;
func StartWorkers(
	logger model.Logger,
	serviceManager *service.Manager,
	sessionManager *session.Manager,
	notifyTLS chan<- *model.Notification,
	notifyReliable chan<- *model.Notification,
	packetDown chan<- *model.Packet,
	packetUp <-chan *model.Packet,
	tlsRecordDown <-chan []byte,
	tlsRecordUp chan<- []byte,
) {
	ws := &workersState{
		logger:         logger,
		serviceManager: serviceManager,
		notifyTLS:      notifyTLS,
		notifyReliable: notifyReliable,
		packetDown:     packetDown,
		packetUp:       packetUp,
		tlsRecordDown:  tlsRecordDown,
		tlsRecordUp:    tlsRecordUp,
		sessionManager: sessionManager,
	}
	serviceManager.StartWorker(ws.moveUpLoop)
	serviceManager.StartWorker(ws.moveDownLoop)
}

// workersState contains the control channel state.
type workersState struct {
	logger         model.Logger
	serviceManager *service.Manager
	notifyTLS      chan<- *model.Notification
	notifyReliable chan<- *model.Notification
	packetDown     chan<- *model.Packet
	packetUp       <-chan *model.Packet
	tlsRecordDown  <-chan []byte
	tlsRecordUp    chan<- []byte
	sessionManager *session.Manager
}
