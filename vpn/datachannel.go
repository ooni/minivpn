package vpn

import (
	"errors"
	"io"
	"log"
	"sync"
)

// dataChannelConn is the data channel's view of the underlying conn.
type dataChannelConn interface {
	// Write writes a user packet.
	Write(packet []byte) error
}

// dataChannelUser is the data channel's view of the VPN user.
type dataChannelUser interface {
	// Read receives a user packet.
	Read(packet []byte) error
}

// dataChannelManager manages the data channel.
type dataChannelManager struct {
	// closeOnce allows to call Close done just once.
	closeOnce *sync.Once

	// configure is the channel used by the Configure method.
	configure chan *dataChannelSettings

	// done indicates we should stop running.
	done chan interface{}	

	// ch is the channel used by the Read.
	readch chan []byte

	// startOnce allows to call Start just once.
	startOnce *sync.Once

	// writech is the channel used by Write.
	writech chan []byte
}

// dataChannelSettings contains settings for the data channel.
type dataChannelSettings struct {
	// local is the local key source.
	local *keySource

	// options contains options.
	options *Options

	// remoteID is the remote session ID.
	remoteID []byte

	// remote is the remote key source.
	remote *keySource

	// sessionID is the local session ID.
	sessionID []byte
}

// newDataChannelManager returns a new data channel manager.
func newDataChannelManager() *dataChannelManager {
	return &dataChannelManager{
		closeOnce: &sync.Once{},
		configure: make(chan *dataChannelSettings),
		done:      make(chan interface{}),
		readch:    make(chan []byte),
		startOnce: &sync.Once{},
		writech:   make(chan []byte),
	}
}

// ErrAlreadyRunning indicates that a background goroutine is already running.
var ErrAlreadyRunning = errors.New("background goroutine is already running")

// Start starts a background goroutine to manage the data channel.
//
// Arguments:
//
// - conn is the thing that manages the underlying connection;
//
// - user is a proxy for the VPN user.
//
// This function returns ErrAlreadyRunning if invoked more than once.
func (dcm *dataChannelManager) Start(conn dataChannelConn, user dataChannelUser) error {
	err := ErrAlreadyRunning
	dcm.startOnce.Do(func() {
		go dcm.loop(conn, user)
		err = nil
	})
	return err
}

// Close closes the data channel. After this function has been called, the
// background goroutine will return and any operation will fail. Subsequent
// calls of this function perform no operation and are safe.
func (dcm *dataChannelManager) Close() error {
	dcm.closeOnce.Do(func() {
		close(dcm.done)
	})
	return nil
}

// Reconfigure reconfigures the data channel. If you don't call this method
// at least once, the data channel will not work.
func (dcm *dataChannelManager) Reconfigure(config *dataChannelSettings) error {
	select {
	case dcm.configure <- config:
		return nil
	case <-dcm.done:
		return io.ErrClosedPipe
	}
}

// Write allows the user to send a packet using the
// underlying OpenVPN conn.
//
// The following diagram shows what happens:
//
//       + ---- +            + ---- +              + -------- +
//       | User | ---------> | loop | -----------> | VPN conn |
//       + ---- +    user    + ---- +     vpn      + -------- +
//                  packet               packet
//
// The user calls Write (this method). Write passes the packet
// to the background loop. The loop wraps the original packet
// into a VPN packet and passes such a packet to the conn.
func (dcm *dataChannelManager) Write(userPacket []byte) error {
	select {
	case <-dcm.done:
		return io.ErrClosedPipe
	case dcm.writech <- userPacket:
		return nil
	}
}

// Read allows the underlying VPN conn to pass us a piece of data.
//
// The following diagram shows what happens:
//
//       + ---- +            + ---- +              + -------- +
//       | User | <--------- | loop | <----------- | VPN conn |
//       + ---- +    user    + ---- +     vpn      + -------- +
//                  packet               packet
//
//
// The VPN conn calls Read (this method). Read passes to packet
// to the background loop. The loop unwraps a user packet from
// the VPN packet and passes it to the user.
func (dcm *dataChannelManager) Read(vpnPacket []byte) error {
	select {
	case <-dcm.done:
		return io.ErrClosedPipe
	case dcm.readch <- vpnPacket:
		return nil
	}
}

// loop is the background loop that manages the data channel.
func (dcm *dataChannelManager) loop(conn dataChannelConn, user dataChannelUser) {
	dcs := &dataChannelState{
		// TODO: initialize
	}
	for {
		select {
		// 0. request to initialize or reinitialize.
		case config := <-dcm.configure:
			err := dcs.setup(config)
			if err != nil {
				log.Printf("warning: %s", err.Error())
				continue
			}

		// 1. we've been asked to stop.
		case <-dcm.done:
			return

		// 2. we need to send a user packet over the VPN.
		case up := <-dcm.writech:
			vp, err := dcs.wrap(up)
			if err != nil {
				log.Printf("warning: %s", err.Error())
				continue
			}
			err = conn.Write(vp)
			if err != nil {
				log.Printf("warning: %s", err.Error())
				continue
			}

		// 3. we need to send a VPN packet to the user
		case vp := <-dcm.readch:
			up, err := dcs.unwrap(vp)
			if err != nil {
				log.Printf("warning: %s", err.Error())
				continue
			}
			err = user.Read(up)
			if err != nil {
				log.Printf("warning: %s", err.Error())
				continue
			}
		}
	}
}

// dataChannelState is the state of the data channel.
type dataChannelState struct {
	// TODO: basically the fields of struct data.
}

// setup configures or reconfigures the data channel state.
func (dcs *dataChannelState) setup(config *dataChannelSettings) error {
	// TODO: equivalent to data.initSession + data.setup
}

// wrap wraps a user packet into a VPN packet.
func (dcs *dataChannelState) wrap(up []byte) ([]byte, error) {
	// TODO: equivalent to data.send without the final send call
}

// unwrap unwraps a user packet from a VPN packet.
func (dcs *dataChannelState) unwrap(vp []byte) ([]byte, error) {
	// TODO: equivalent to data.handleIn without the final channel write
}
