package tlsstate

import (
	"context"
	"net"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
	tls "github.com/refraction-networking/utls"
)

// Service is the tlsstate service. Make sure you initialize
// the channels before invoking [Service.StartWorkers].
type Service struct {
	NotifyTLS     chan *model.Notification
	TLSRecordUp   chan []byte
	TLSRecordDown *chan []byte
}

// StartWorkers starts the tls-state workers. See the [ARCHITECTURE]
// file for more information about the packet-muxer workers.
//
// [ARCHITECTURE]: https://github.com/ooni/minivpn/blob/main/ARCHITECTURE.md
func (svc *Service) StartWorkers(
	logger model.Logger,
	workersManager *workers.Manager,
	sessionManager *session.Manager,
	options *model.Options,
) {
	ws := &workersState{
		logger:         logger,
		notifyTLS:      svc.NotifyTLS,
		options:        options,
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
	options        *model.Options
	tlsRecordDown  chan<- []byte
	tlsRecordUp    <-chan []byte
	sessionManager *session.Manager
	workersManager *workers.Manager
}

// worker is the main loop of the tlsstate
func (ws *workersState) worker() {
	defer func() {
		ws.workersManager.OnWorkerDone()
		ws.workersManager.StartShutdown()
		ws.logger.Debug("tlsstate: worker: done")
	}()

	ws.logger.Debug("tlsstate: worker: started")
	for {
		select {
		case notif := <-ws.notifyTLS:
			if (notif.Flags & model.NotificationReset) != 0 {
				if err := ws.tlsAuth(); err != nil {
					ws.logger.Warnf("tlsstate: tlsAuth: %s", err.Error())
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
	conn := newTLSBio(ws.tlsRecordUp, ws.tlsRecordDown)
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

	// make sure we timeout after 60 seconds anyway
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	select {
	case err := <-errorch:
		return err

	case <-ctx.Done():
		return ctx.Err()

	case <-ws.workersManager.ShouldShutdown():
		return workers.ErrShutdown
	}
}

// doTLSAuth is the internal implementation of tlsAuth.
func (ws *workersState) doTLSAuth(conn net.Conn, config *tls.Config, errorch chan<- error) {
	ws.logger.Debug("tlsstate: doTLSAuth: started")
	defer ws.logger.Debug("tlsstate: doTLSAuth: done")

	tlsConn, err := tlsHandshakeFn(conn, config)
	if err != nil {
		errorch <- err
		return
	}
	defer tlsConn.Close()

	_ = tlsConn

	errorch <- nil
}
