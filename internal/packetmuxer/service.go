// Package packetmuxer implements the packet-muxer workers.
package packetmuxer

import (
	"errors"
	"fmt"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
)

var (
	serviceName = "packetmuxer"
)

const (
	// A sufficiently long wakup period to initialize a ticker with.
	longWakeup = time.Hour * 24 * 30
)

// Service is the packetmuxer service. Make sure you initialize
// the channels before invoking [Service.StartWorkers].
type Service struct {
	// HardReset receives requests to initiate a hard reset, that will start the openvpn handshake.
	HardReset chan any

	// NotifyTLS sends reset notifications to tlsstate.
	NotifyTLS *chan *model.Notification

	// MuxerToReliable moves packets up to reliabletransport.
	MuxerToReliable *chan *model.Packet

	// MuxerToData moves packets up to the datachannel.
	MuxerToData *chan *model.Packet

	// DataOrControlToMuxer moves packets down from the reliabletransport or datachannel.
	DataOrControlToMuxer chan *model.Packet

	// MuxerToNetwork moves bytes down to the networkio layer below us.
	MuxerToNetwork *chan []byte

	// NetworkToMuxer moves bytes up to us from the networkio layer below.
	NetworkToMuxer chan []byte
}

// StartWorkers starts the packet-muxer workers. See the [ARCHITECTURE]
// file for more information about the packet-muxer workers.
//
// [ARCHITECTURE]: https://github.com/ooni/minivpn/blob/main/ARCHITECTURE.md
func (s *Service) StartWorkers(
	config *model.Config,
	workersManager *workers.Manager,
	sessionManager *session.Manager,
) {
	ws := &workersState{
		logger:    config.Logger(),
		hardReset: s.HardReset,
		// initialize to a sufficiently long time from now
		hardResetTicker:      time.NewTicker(longWakeup),
		notifyTLS:            *s.NotifyTLS,
		dataOrControlToMuxer: s.DataOrControlToMuxer,
		muxerToReliable:      *s.MuxerToReliable,
		muxerToData:          *s.MuxerToData,
		muxerToNetwork:       *s.MuxerToNetwork,
		networkToMuxer:       s.NetworkToMuxer,
		sessionManager:       sessionManager,
		workersManager:       workersManager,
	}
	workersManager.StartWorker(ws.moveUpWorker)
	workersManager.StartWorker(ws.moveDownWorker)
}

// workersState contains the reliabletransport workers state.
type workersState struct {
	// logger is the logger to use
	logger model.Logger

	// hardReset is the channel posted to force a hard reset.
	hardReset <-chan any

	// how many times have we sent the initial hardReset packet
	hardResetCount int

	// hardResetTicker is a channel to retry the initial send of hard reset packet.
	hardResetTicker *time.Ticker

	// notifyTLS is used to send notifications to the TLS service.
	notifyTLS chan<- *model.Notification

	// dataOrControlToMuxer is the channel for reading all the packets traveling down the stack.
	dataOrControlToMuxer <-chan *model.Packet

	// muxerToReliable is the channel for writing control packets going up the stack.
	muxerToReliable chan<- *model.Packet

	// muxerToData is the channel for writing data packets going up the stack.
	muxerToData chan<- *model.Packet

	// muxerToNetwork is the channel for writing raw packets going down the stack.
	muxerToNetwork chan<- []byte

	// networkToMuxer is the channel for reading raw packets going up the stack.
	networkToMuxer <-chan []byte

	// sessionManager manages the OpenVPN session.
	sessionManager *session.Manager

	// workersManager controls the workers lifecycle.
	workersManager *workers.Manager
}

// moveUpWorker moves packets up the stack
func (ws *workersState) moveUpWorker() {
	workerName := fmt.Sprintf("%s: moveUpWorker", serviceName)

	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)

	for {
		// POSSIBLY BLOCK awaiting for incoming raw packet
		select {
		case rawPacket := <-ws.networkToMuxer:
			if err := ws.handleRawPacket(rawPacket); err != nil {
				// error already printed
				return
			}

		case <-ws.hardResetTicker.C:
			// retry the hard reset, it probably was lost
			if err := ws.startHardReset(); err != nil {
				// error already logged
				return
			}

		case <-ws.hardReset:
			if err := ws.startHardReset(); err != nil {
				// error already logged
				return
			}

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}

// moveDownWorker moves packets down the stack
func (ws *workersState) moveDownWorker() {
	workerName := fmt.Sprintf("%s: moveDownWorker", serviceName)

	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)

	for {
		// POSSIBLY BLOCK on reading the packet moving down the stack
		select {
		case packet := <-ws.dataOrControlToMuxer:
			// serialize the packet
			rawPacket, err := packet.Bytes()
			if err != nil {
				ws.logger.Warnf("%s: cannot serialize packet: %s", workerName, err.Error())
				continue
			}

			// POSSIBLY BLOCK on writing the packet to the networkio layer.
			// [ARCHITECTURE]: https://github.com/ooni/minivpn/blob/main/ARCHITECTURE.md

			select {
			case ws.muxerToNetwork <- rawPacket:
				// nothing
			case <-ws.workersManager.ShouldShutdown():
				return
			}

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}

// startHardReset is invoked when we need to perform a HARD RESET.
func (ws *workersState) startHardReset() error {
	ws.hardResetCount += 1

	// emit a CONTROL_HARD_RESET_CLIENT_V2 pkt
	packet := ws.sessionManager.NewHardResetPacket()
	if err := ws.serializeAndEmit(packet); err != nil {
		return err
	}

	// resend if not received the server's reply in 2 seconds.
	ws.hardResetTicker.Reset(time.Second * 2)

	// reset the state to become initial again.
	ws.sessionManager.SetNegotiationState(session.S_PRE_START)

	// TODO: any other change to apply in this case?

	return nil
}

// handleRawPacket is the code invoked to handle a raw packet.
func (ws *workersState) handleRawPacket(rawPacket []byte) error {
	// make sense of the packet
	packet, err := model.ParsePacket(rawPacket)
	if err != nil {
		ws.logger.Warnf("packetmuxer: moveUpWorker: ParsePacket: %s", err.Error())
		return nil // keep running
	}

	// handle the case where we're performing a HARD_RESET
	if ws.sessionManager.NegotiationState() == session.S_PRE_START &&
		packet.Opcode == model.P_CONTROL_HARD_RESET_SERVER_V2 {
		packet.Log(ws.logger, model.DirectionIncoming)
		ws.hardResetTicker.Stop()
		return ws.finishThreeWayHandshake(packet)
	}

	// multiplex the incoming packet POSSIBLY BLOCKING on delivering it
	if packet.IsControl() || packet.Opcode == model.P_ACK_V1 {
		select {
		case ws.muxerToReliable <- packet:
		case <-ws.workersManager.ShouldShutdown():
			return workers.ErrShutdown
		}
	} else {
		if ws.sessionManager.NegotiationState() < session.S_GENERATED_KEYS {
			// A well-behaved server should not send us data packets
			// before we have a working session. Under normal operations, the
			// connection in the client side should pick a different port,
			// so that data sent from previous sessions will not be delivered.
			// However, it does not harm to be defensive here.
			return errors.New("not ready to handle data")
		}
		select {
		case ws.muxerToData <- packet:
		case <-ws.workersManager.ShouldShutdown():
			return workers.ErrShutdown
		}
	}

	return nil
}

// finishThreeWayHandshake responds to the HARD_RESET_SERVER and finishes the handshake.
func (ws *workersState) finishThreeWayHandshake(packet *model.Packet) error {
	// register the server's session (note: the PoV is the server's one)
	ws.sessionManager.SetRemoteSessionID(packet.LocalSessionID)

	// advance the state
	ws.sessionManager.SetNegotiationState(session.S_START)

	// pass the packet up so that we can ack it properly
	select {
	case ws.muxerToReliable <- packet:
	case <-ws.workersManager.ShouldShutdown():
		return workers.ErrShutdown
	}

	// attempt to tell TLS we want to handshake.
	// This WILL BLOCK if the notifyTLS channel
	// is Full, but we make sure we control that we don't pass spurious soft-reset packets while we're
	// doing a handshake.
	select {
	case ws.notifyTLS <- &model.Notification{Flags: model.NotificationReset}:
		// nothing
	case <-ws.workersManager.ShouldShutdown():
		return workers.ErrShutdown
	}

	return nil
}

// serializeAndEmit will write a serialized packet on the channel going down to the networkio layer.
func (ws *workersState) serializeAndEmit(packet *model.Packet) error {
	// serialize it
	rawPacket, err := packet.Bytes()
	if err != nil {
		return err
	}

	// emit the packet. Possibly BLOCK writing to the networkio layer.
	select {
	case ws.muxerToNetwork <- rawPacket:
		// nothing

	case <-ws.workersManager.ShouldShutdown():
		return workers.ErrShutdown
	}

	packet.Log(ws.logger, model.DirectionOutgoing)
	return nil
}
