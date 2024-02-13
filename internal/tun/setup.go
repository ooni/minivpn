package tun

import (
	"github.com/ooni/minivpn/internal/controlchannel"
	"github.com/ooni/minivpn/internal/datachannel"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/networkio"
	"github.com/ooni/minivpn/internal/packetmuxer"
	"github.com/ooni/minivpn/internal/reliabletransport"
	"github.com/ooni/minivpn/internal/runtimex"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/tlssession"
	"github.com/ooni/minivpn/internal/workers"
)

// connectChannel connects an existing channel (a "signal" in Qt terminology)
// to a nil pointer to channel (a "slot" in Qt terminology).
func connectChannel[T any](signal chan T, slot **chan T) {
	runtimex.Assert(signal != nil, "signal is nil")
	runtimex.Assert(slot == nil || *slot == nil, "slot or *slot aren't nil")
	*slot = &signal
}

// startWorkers starts all the workers.  See the [ARCHITECTURE]
// file for more information about the workers.
//
// [ARCHITECTURE]: https://github.com/ooni/minivpn/blob/main/ARCHITECTURE.md
func startWorkers(config *model.Config, conn networkio.FramingConn,
	sessionManager *session.Manager, tunDevice *TUN) *workers.Manager {

	// create a workers manager
	workersManager := workers.NewManager(config.Logger())

	// create the networkio service.
	nio := &networkio.Service{
		MuxerToNetwork: make(chan []byte),
		NetworkToMuxer: nil,
	}

	// create the packetmuxer service.
	muxer := &packetmuxer.Service{
		MuxerToReliable:      nil,
		MuxerToData:          nil,
		NotifyTLS:            nil,
		HardReset:            make(chan any, 1),
		DataOrControlToMuxer: make(chan *model.Packet),
		MuxerToNetwork:       nil,
		NetworkToMuxer:       make(chan []byte),
	}

	// connect networkio and packetmuxer
	connectChannel(nio.MuxerToNetwork, &muxer.MuxerToNetwork)
	connectChannel(muxer.NetworkToMuxer, &nio.NetworkToMuxer)

	// create the datachannel service.
	datach := &datachannel.Service{
		MuxerToData:          make(chan *model.Packet),
		DataOrControlToMuxer: nil,
		KeyReady:             make(chan *session.DataChannelKey, 1),
		TUNToData:            tunDevice.tunDown,
		DataToTUN:            tunDevice.tunUp,
	}

	// connect the packetmuxer and the datachannel
	connectChannel(datach.MuxerToData, &muxer.MuxerToData)
	connectChannel(muxer.DataOrControlToMuxer, &datach.DataOrControlToMuxer)

	// create the reliabletransport service.
	rel := &reliabletransport.Service{
		DataOrControlToMuxer: nil,
		ControlToReliable:    make(chan *model.Packet),
		MuxerToReliable:      make(chan *model.Packet),
		ReliableToControl:    nil,
	}

	// connect reliable service and packetmuxer.
	connectChannel(rel.MuxerToReliable, &muxer.MuxerToReliable)
	connectChannel(muxer.DataOrControlToMuxer, &rel.DataOrControlToMuxer)

	// create the controlchannel service.
	ctrl := &controlchannel.Service{
		NotifyTLS:            nil,
		ControlToReliable:    nil,
		ReliableToControl:    make(chan *model.Packet),
		TLSRecordToControl:   make(chan []byte),
		TLSRecordFromControl: nil,
	}

	// connect the reliable service and the controlchannel service
	connectChannel(rel.ControlToReliable, &ctrl.ControlToReliable)
	connectChannel(ctrl.ReliableToControl, &rel.ReliableToControl)

	// create the tlssession service
	tlsx := &tlssession.Service{
		NotifyTLS:     make(chan *model.Notification, 1),
		KeyUp:         nil,
		TLSRecordUp:   make(chan []byte),
		TLSRecordDown: nil,
	}

	// connect the tlsstate service and the controlchannel service
	connectChannel(tlsx.NotifyTLS, &ctrl.NotifyTLS)
	connectChannel(tlsx.TLSRecordUp, &ctrl.TLSRecordFromControl)
	connectChannel(ctrl.TLSRecordToControl, &tlsx.TLSRecordDown)

	// connect tlsstate service and the datachannel service
	connectChannel(datach.KeyReady, &tlsx.KeyUp)

	// connect the muxer and the tlsstate service
	connectChannel(tlsx.NotifyTLS, &muxer.NotifyTLS)

	// start all the workers
	nio.StartWorkers(config, workersManager, conn)
	muxer.StartWorkers(config, workersManager, sessionManager)
	rel.StartWorkers(config, workersManager, sessionManager)
	ctrl.StartWorkers(config, workersManager, sessionManager)
	datach.StartWorkers(config, workersManager, sessionManager)
	tlsx.StartWorkers(config, workersManager, sessionManager)

	// tell the packetmuxer that it should handshake ASAP
	muxer.HardReset <- true

	return workersManager
}
