package tlssession

import (
	"fmt"
	"net"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
	tls "github.com/refraction-networking/utls"
)

var (
	serviceName = "tlssession"
)

// Service is the tlssession service. Make sure you initialize
// the channels before invoking [Service.StartWorkers].
type Service struct {
	// NotifyTLS is a channel where we receive incoming notifications.
	NotifyTLS chan *model.Notification

	// KeyUP is used to send newly negotiated data channel keys ready to be
	// used.
	KeyUp *chan *session.DataChannelKey

	// TLSRecordUp is data coming up from the control channel layer to us.
	// TODO(ainghazal): considere renaming when we have merged the whole
	// set of components. This name might not give a good idea of what the bytes being
	// moved around are - this is a serialized control channel packet, which is
	// mainly used to do the initial handshake and then receive control
	// packets encrypted with this TLS session.
	TLSRecordUp chan []byte

	// TLSRecordDown is data being transferred down from us to the control
	// channel.
	TLSRecordDown *chan []byte
}

// StartWorkers starts the tlssession workers. See the [ARCHITECTURE]
// file for more information about the packet-muxer workers.
//
// [ARCHITECTURE]: https://github.com/ooni/minivpn/blob/main/ARCHITECTURE.md
func (svc *Service) StartWorkers(
	config *model.Config,
	workersManager *workers.Manager,
	sessionManager *session.Manager,
) {
	ws := &workersState{
		keyUp:          *svc.KeyUp,
		logger:         config.Logger(),
		notifyTLS:      svc.NotifyTLS,
		options:        config.OpenVPNOptions(),
		tlsRecordDown:  *svc.TLSRecordDown,
		tlsRecordUp:    svc.TLSRecordUp,
		sessionManager: sessionManager,
		workersManager: workersManager,
	}
	workersManager.StartWorker(ws.worker)
}

// workersState contains the control channel state.
type workersState struct {
	logger         model.Logger
	notifyTLS      <-chan *model.Notification
	options        *model.OpenVPNOptions
	tlsRecordDown  chan<- []byte
	tlsRecordUp    <-chan []byte
	keyUp          chan<- *session.DataChannelKey
	sessionManager *session.Manager
	workersManager *workers.Manager
}

// worker is the main loop of the tlssession
func (ws *workersState) worker() {
	workerName := fmt.Sprintf("%s: worker", serviceName)

	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)
	for {
		select {
		case notif := <-ws.notifyTLS:
			if (notif.Flags & model.NotificationReset) != 0 {
				if err := ws.tlsAuth(); err != nil {
					ws.logger.Warnf("%s: %s", workerName, err.Error())
					// TODO: is it worth checking the return value and stopping?
				}
			}

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}

// tlsAuth runs the TLS auth algorithm
func (ws *workersState) tlsAuth() error {
	// create the BIO to use channels as a socket
	conn := newTLSBio(ws.logger, ws.tlsRecordUp, ws.tlsRecordDown)
	defer conn.Close()

	// we construct the certCfg from options, that has access to the certificate material
	certCfg, err := newCertConfigFromOptions(ws.options)
	if err != nil {
		return err
	}

	// tlsConf is a tls.Config obtained from our own initialization function
	tlsConf, err := initTLSFn(certCfg)
	if err != nil {
		return err
	}

	// run the real algorithm in a background goroutine
	errorch := make(chan error)
	go ws.doTLSAuth(conn, tlsConf, errorch)

	select {
	case err := <-errorch:
		return err

	case <-ws.workersManager.ShouldShutdown():
		return workers.ErrShutdown
	}
}

// doTLSAuth is the internal implementation of tlsAuth such that tlsAuth
// can interrupt this function early if needed.
func (ws *workersState) doTLSAuth(conn net.Conn, config *tls.Config, errorch chan<- error) {
	ws.logger.Debug("tlsession: doTLSAuth: started")
	defer ws.logger.Debug("tlssession: doTLSAuth: done")

	// do the TLS handshake
	tlsConn, err := tlsHandshakeFn(conn, config)
	if err != nil {
		errorch <- err
		return
	}
	// In case you're wondering why we don't need to close the conn:
	// we don't care since the underlying conn is a tlsBio
	// defer tlsConn.Close()

	// we need the active key to create the first control message
	activeKey, err := ws.sessionManager.ActiveKey()
	if err != nil {
		errorch <- err
		return
	}

	// send the first control message with random material
	if err := ws.sendAuthRequestMessage(tlsConn, activeKey); err != nil {
		errorch <- err
		return
	}
	ws.sessionManager.SetNegotiationState(session.S_SENT_KEY)

	// read the server's keySource and options
	remoteKey, serverOptions, err := ws.recvAuthReplyMessage(tlsConn)
	if err != nil {
		errorch <- err
		return
	}
	ws.logger.Debugf("Remote options: %s", serverOptions)

	// init the tunnel info
	if err := ws.sessionManager.InitTunnelInfo(serverOptions); err != nil {
		errorch <- err
		return
	}

	// add the remote key to the active key
	activeKey.AddRemoteKey(remoteKey)
	ws.sessionManager.SetNegotiationState(session.S_GOT_KEY)

	// send the push request
	if err := ws.sendPushRequestMessage(tlsConn); err != nil {
		errorch <- err
		return
	}

	// obtain tunnel info from the push response
	tinfo, err := ws.recvPushResponseMessage(tlsConn)
	if err != nil {
		errorch <- err
		return
	}

	// update with extra information obtained from push response
	ws.sessionManager.UpdateTunnelInfo(tinfo)

	// progress to the ACTIVE state
	ws.sessionManager.SetNegotiationState(session.S_ACTIVE)

	// notify the datachannel that we've got a key pair ready to use
	ws.keyUp <- activeKey

	errorch <- nil
}

// sendAuthRequestMessage sends the auth request message
func (ws *workersState) sendAuthRequestMessage(tlsConn net.Conn, activeKey *session.DataChannelKey) error {
	// this message is sending our options and asking the server to get AUTH
	ctrlMsg, err := encodeClientControlMessageAsBytes(activeKey.Local(), ws.options)
	if err != nil {
		return err
	}

	// let's fire off the message
	_, err = tlsConn.Write(ctrlMsg)
	return err
}

// recvAuthReplyMessage reads and parses the first control response.
func (ws *workersState) recvAuthReplyMessage(conn net.Conn) (*session.KeySource, string, error) {
	// read raw bytes
	buffer := make([]byte, 1<<17)
	count, err := conn.Read(buffer)
	if err != nil {
		return nil, "", err
	}
	data := buffer[:count]

	// parse what we received
	return parseServerControlMessage(data)
}

// sendPushRequestMessage sends the push request message
func (ws *workersState) sendPushRequestMessage(conn net.Conn) error {
	data := append([]byte("PUSH_REQUEST"), 0x00)
	_, err := conn.Write(data)
	return err
}

// recvPushResponseMessage receives and parses the push response message
func (ws *workersState) recvPushResponseMessage(conn net.Conn) (*model.TunnelInfo, error) {
	// read raw bytes
	buffer := make([]byte, 1<<17)
	count, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}
	data := buffer[:count]

	// parse what we received
	return parseServerPushReply(ws.logger, data)
}
