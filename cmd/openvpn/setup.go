package main

import (
	"github.com/ooni/minivpn/internal/controlchannel"
	"github.com/ooni/minivpn/internal/datachannel"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/networkio"
	"github.com/ooni/minivpn/internal/packetmuxer"
	"github.com/ooni/minivpn/internal/reliable"
	"github.com/ooni/minivpn/internal/runtimex"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/tlsstate"
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
func startWorkers(logger model.Logger, sessionManager *session.Manager,
	conn networkio.FramingConn, options *model.Options) *workers.Manager {
	// create a workers manager
	workersManager := workers.NewManager()

	// create the networkio service.
	nio := &networkio.Service{
		RawPacketDown: make(chan []byte, 1<<5),
		RawPacketUp:   nil, // ok
	}

	// create the packetmuxer service.
	muxer := &packetmuxer.Service{
		ControlPacketUp: nil, // ok
		DataPacketUp:    nil, // ok
		NotifyTLS:       nil,
		HardReset:       make(chan any, 1),
		PacketDown:      make(chan *model.Packet),
		RawPacketDown:   nil, // ok
		RawPacketUp:     make(chan []byte),
	}

	// tell the packetmuxer that it should handshake ASAP
	muxer.HardReset <- true

	// connect networkio and packetmuxer
	connectChannel(nio.RawPacketDown, &muxer.RawPacketDown)
	connectChannel(muxer.RawPacketUp, &nio.RawPacketUp)

	// create the datachannel service.
	datach := &datachannel.Service{
		DataPacketUp: make(chan *model.Packet),
	}

	// connect the packetmuxer and the datachannel
	connectChannel(datach.DataPacketUp, &muxer.DataPacketUp)

	// create the reliable service.
	rel := &reliable.Service{
		PacketDownBottom: nil, // ok
		PacketDownTop:    make(chan *model.Packet),
		PacketUpBottom:   make(chan *model.Packet),
		PacketUpTop:      nil, // ok
	}

	// connect reliable service and packetmuxer.
	connectChannel(rel.PacketUpBottom, &muxer.ControlPacketUp)
	connectChannel(muxer.PacketDown, &rel.PacketDownBottom)

	// create the controlchannel service.
	ctrl := &controlchannel.Service{
		NotifyTLS:     nil, // ok
		PacketDown:    nil, // ok
		PacketUp:      make(chan *model.Packet),
		TLSRecordDown: make(chan []byte),
		TLSRecordUp:   nil, // ok
	}

	// connect the reliable service and the controlchannel service
	connectChannel(rel.PacketDownTop, &ctrl.PacketDown)
	connectChannel(ctrl.PacketUp, &rel.PacketUpTop)

	// create the tlsstate service
	tlsx := &tlsstate.Service{
		NotifyTLS:     make(chan *model.Notification, 1),
		TLSRecordUp:   make(chan []byte),
		TLSRecordDown: nil,
	}

	// connect the tlsstate service and the controlchannel service
	connectChannel(tlsx.NotifyTLS, &ctrl.NotifyTLS)
	connectChannel(tlsx.TLSRecordUp, &ctrl.TLSRecordUp)
	connectChannel(ctrl.TLSRecordDown, &tlsx.TLSRecordDown)

	// connect the muxer and the tlsstate service
	connectChannel(tlsx.NotifyTLS, &muxer.NotifyTLS)

	logger.Debugf("%T: %+v", nio, nio)
	logger.Debugf("%T: %+v", muxer, muxer)
	logger.Debugf("%T: %+v", rel, rel)
	logger.Debugf("%T: %+v", ctrl, ctrl)
	logger.Debugf("%T: %+v", tlsx, tlsx)

	// start all the workers
	nio.StartWorkers(logger, workersManager, conn)
	muxer.StartWorkers(logger, workersManager, sessionManager)
	rel.StartWorkers(logger, workersManager, sessionManager)
	ctrl.StartWorkers(logger, workersManager, sessionManager)
	tlsx.StartWorkers(logger, workersManager, sessionManager, options)

	return workersManager
}
