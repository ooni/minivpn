package reliabletransport

import (
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
)

var (
	serviceName = "reliabletransport"
)

// Service is the reliable service. Make sure you initialize
// the channels before invoking [Service.StartWorkers].
type Service struct {
	// DataOrControlToMuxer is a shared channel that moves packets down to the muxer
	DataOrControlToMuxer *chan *model.Packet

	// ControlToReliable moves packets down to us
	ControlToReliable chan *model.Packet

	// MuxerToReliable moves packets up to us
	MuxerToReliable chan *model.Packet

	// ReliableToControl moves packets up from us to the control layer above
	ReliableToControl *chan *model.Packet
}

// StartWorkers starts the reliable-transport workers. See the [ARCHITECTURE]
// file for more information about the reliable-transport workers.
//
// [ARCHITECTURE]: https://github.com/ooni/minivpn/blob/main/ARCHITECTURE.md
func (s *Service) StartWorkers(
	config *model.Config,
	workersManager *workers.Manager,
	sessionManager *session.Manager,
) {
	ws := &workersState{
		controlToReliable:    s.ControlToReliable,
		dataOrControlToMuxer: *s.DataOrControlToMuxer,
		incomingSeen:         make(chan incomingPacketSeen, 100),
		logger:               config.Logger(),
		// incomingSeen is a buffered channel to avoid losing packets if we're busy
		// processing in the sender goroutine.
		muxerToReliable:   s.MuxerToReliable,
		reliableToControl: *s.ReliableToControl,
		sessionManager:    sessionManager,
		tracer:            config.Tracer(),
		workersManager:    workersManager,
	}
	workersManager.StartWorker(ws.moveUpWorker)
	workersManager.StartWorker(ws.moveDownWorker)
}

// workersState contains the reliable workers state
type workersState struct {
	// controlToReliable is the channel from which we read packets going down the stack.
	controlToReliable <-chan *model.Packet

	// dataOrControlToMuxer is the channel where we write packets going down the stack.
	dataOrControlToMuxer chan<- *model.Packet

	// incomingSeen ins the shared channel to connect sender and receiver goroutines.
	incomingSeen chan incomingPacketSeen

	// logger is the logger to use
	logger model.Logger

	// muxerToReliable is the channel from which we read packets going up the stack.
	muxerToReliable <-chan *model.Packet

	// reliableToControl is the channel where we write packets going up the stack.
	reliableToControl chan<- *model.Packet

	// sessionManager manages the OpenVPN session.
	sessionManager *session.Manager

	// tracer is a handshake tracer.
	tracer model.HandshakeTracer

	// workersManager controls the workers lifecycle.
	workersManager *workers.Manager
}
