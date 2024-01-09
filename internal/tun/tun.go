// Package tun implements the tun API for the minivpn client.
package tun

// TODO(ainghazal): this package is almost identical to tlsbio, consider refactoring.

import (
	"bytes"
	"context"
	"net"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/networkio"
	"github.com/ooni/minivpn/internal/session"
)

func StartTUN(conn networkio.FramingConn, options *model.Options) *TUN {
	// create a session
	sessionManager, err := session.NewManager(log.Log)
	if err != nil {
		log.WithError(err).Fatal("tun.StartTUN")
	}

	// create the TUN that will OWN the connection
	tunnel := NewTUN(log.Log, conn, sessionManager)

	// start all the workers
	workers := startWorkers(log.Log, sessionManager, tunnel, conn, options)
	tunnel.WhenDone(func() {
		workers.StartShutdown()
		workers.WaitWorkersShutdown()
	})

	// signal to the session manager that we're ready to start accepting data.
	// In practice, this means that we already have a valid TunnelInfo at this point
	// (i.e., three way handshake has completed, and we have valid keys).
	<-sessionManager.Ready
	return tunnel
}

// tunBio allows to use channels to read and write
type TUN struct {
	TunDown          chan []byte
	TunUp            chan []byte
	conn             networkio.FramingConn
	logger           model.Logger
	closeOnce        sync.Once
	hangup           chan any
	readBuffer       *bytes.Buffer
	session          *session.Manager
	readDeadline     *time.Timer
	readDeadlineDone chan any
	whenDone         func()
}

// newTUN creates a new TUN.
// This function TAKES OWNERSHIP of the conn.
func NewTUN(logger model.Logger, conn networkio.FramingConn, session *session.Manager) *TUN {
	return &TUN{
		TunDown:          make(chan []byte),
		TunUp:            make(chan []byte, 10),
		conn:             conn,
		closeOnce:        sync.Once{},
		hangup:           make(chan any),
		logger:           logger,
		readBuffer:       &bytes.Buffer{},
		readDeadlineDone: make(chan any),
		session:          session,
	}
}

func (t *TUN) WhenDone(fn func()) {
	t.whenDone = fn
}

func (t *TUN) Close() error {
	t.closeOnce.Do(func() {
		close(t.hangup)
		// We OWN the connection
		t.conn.Close()
		// execute any shutdown callback (useful to propagate shutdown to workers)
		if t.whenDone != nil {
			t.whenDone()
		}
	})
	return nil
}

func (t *TUN) Read(data []byte) (int, error) {
	// log.Printf("[tunbio] requested read")
	for {
		count, _ := t.readBuffer.Read(data)
		if count > 0 {
			// log.Printf("[tunbio] received %d bytes", len(data))
			return count, nil
		}
		select {
		case <-t.readDeadlineDone:
			return 0, context.DeadlineExceeded
		case extra := <-t.TunUp:
			t.readBuffer.Write(extra)
		case <-t.hangup:
			return 0, net.ErrClosed
		}
	}
}

func (t *TUN) Write(data []byte) (int, error) {
	// log.Printf("[tunbio] requested to write %d bytes", len(data))
	select {
	case t.TunDown <- data:
		return len(data), nil
	case <-t.hangup:
		return 0, net.ErrClosed
	}
}

// These methods are specific for TUNBio, not in TLSBio

func (t *TUN) LocalAddr() net.Addr {
	// TODO block or fail if session not ready
	ip := t.session.TunnelInfo().IP
	return &tunBioAddr{ip}
}

func (t *TUN) RemoteAddr() net.Addr {
	// TODO block or fail if session not ready
	gw := t.session.TunnelInfo().GW
	return &tunBioAddr{gw}
}

func (t *TUN) SetDeadline(tm time.Time) error {
	t.logger.Infof("TODO should set deadline", t)
	return nil
}

func (t *TUN) SetReadDeadline(tm time.Time) error {
	// If there's an existing timer, stop it
	if t.readDeadline != nil {
		t.readDeadline.Stop()
	}
	// Calculate the duration until the deadline
	duration := time.Until(tm)
	// Create a new timer
	t.readDeadline = time.AfterFunc(duration, func() {
		t.readDeadlineDone <- true
	})
	return nil
}

func (t *TUN) SetWriteDeadline(tm time.Time) error {
	t.logger.Infof("TODO should set write deadline: %v", tm)
	return nil
}

// tunBioAddr is the type of address returned by [Conn]
type tunBioAddr struct {
	addr string
}

var _ net.Addr = &tunBioAddr{}

// Network implements net.Addr
func (t *tunBioAddr) Network() string {
	return "tunBioAddr"
}

// String implements net.Addr
func (t *tunBioAddr) String() string {
	return t.addr
}
