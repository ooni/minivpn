package tun

// TODO(ainghazal): this package shares a bunch of code with tlsbio, consider
// refactoring common parts.

import (
	"bytes"
	"net"
	"os"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/networkio"
	"github.com/ooni/minivpn/internal/session"
)

// StartTUN initializes and starts the TUN device over the vpn.
func StartTUN(conn networkio.FramingConn, options *model.Options) *TUN {
	// create a session
	sessionManager, err := session.NewManager(log.Log)
	if err != nil {
		log.WithError(err).Fatal("tun.StartTUN")
	}

	// create the TUN that will OWN the connection
	tunnel := newTUN(log.Log, conn, sessionManager)

	// start all the workers
	workers := startWorkers(log.Log, sessionManager, tunnel, conn, options)
	tunnel.whenDone(func() {
		workers.StartShutdown()
		workers.WaitWorkersShutdown()
	})

	// Await for the signal from the session manager to known we're ready to start accepting data.
	// In practice, this means that we already have a valid TunnelInfo at this point
	// (i.e., three way handshake has completed, and we have valid keys).

	// TODO(ainghazal): we need to timeout here.
	<-sessionManager.Ready
	return tunnel
}

// TUN allows to use channels to read and write. It also OWNS the underlying connection.
// TUN implements net.Conn
type TUN struct {
	logger model.Logger

	// tunDown moves bytes down to the data channel.
	tunDown chan []byte

	// tunUp moves bytes up from the data channel.
	tunUp chan []byte

	// conn is the underlying connection.
	conn networkio.FramingConn

	// hangup is used to let methods know the connection is closed.
	hangup chan any

	// ensure idempotency.
	closeOnce sync.Once

	// network is the underlying network for the passed [networkio.FramingConn].
	network string

	// used to buffer reads from above.
	readBuffer *bytes.Buffer

	readDeadline  tunDeadline
	writeDeadline tunDeadline

	session *session.Manager

	// callback to be executed on shutdown.
	whenDoneFn func()
}

// newTUN creates a new TUN.
// This function TAKES OWNERSHIP of the conn.
func newTUN(logger model.Logger, conn networkio.FramingConn, session *session.Manager) *TUN {
	return &TUN{
		logger:        logger,
		tunDown:       make(chan []byte),
		tunUp:         make(chan []byte, 10),
		conn:          conn,
		hangup:        make(chan any),
		closeOnce:     sync.Once{},
		readBuffer:    &bytes.Buffer{},
		network:       conn.LocalAddr().Network(),
		readDeadline:  makeTUNDeadline(),
		writeDeadline: makeTUNDeadline(),
		session:       session,
		whenDoneFn: func() {
		},
	}
}

// whenDone registers a callback to be called on shutdown.
// This is useful to propagate shutdown to workers.
func (t *TUN) whenDone(fn func()) {
	t.whenDoneFn = fn
}

func (t *TUN) Close() error {
	t.closeOnce.Do(func() {
		close(t.hangup)
		// We OWN the connection
		t.conn.Close()
		// execute any shutdown callback
		t.whenDoneFn()
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
		switch {
		case isClosedChan(t.readDeadline.wait()):
			return 0, os.ErrDeadlineExceeded
		}
		select {
		case extra := <-t.tunUp:
			t.readBuffer.Write(extra)
		case <-t.hangup:
			return 0, net.ErrClosed
		case <-t.readDeadline.wait():
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (t *TUN) Write(data []byte) (int, error) {
	// log.Printf("[tunbio] requested to write %d bytes", len(data))
	switch {
	case isClosedChan(t.writeDeadline.wait()):
		return 0, os.ErrDeadlineExceeded
	}
	select {
	case t.tunDown <- data:
		return len(data), nil
	case <-t.hangup:
		return 0, net.ErrClosed
	case <-t.writeDeadline.wait():
		return 0, os.ErrDeadlineExceeded
	}
}

func (t *TUN) LocalAddr() net.Addr {
	// TODO block or fail if session not ready
	ip := t.session.TunnelInfo().IP
	return &tunBioAddr{ip, t.network}
}

func (t *TUN) RemoteAddr() net.Addr {
	// TODO block or fail if session not ready
	gw := t.session.TunnelInfo().GW
	return &tunBioAddr{gw, t.network}
}

func (t *TUN) SetDeadline(tm time.Time) error {
	t.readDeadline.set(tm)
	t.writeDeadline.set(tm)
	return nil
}

func (t *TUN) SetReadDeadline(tm time.Time) error {
	t.readDeadline.set(tm)
	return nil
}

func (t *TUN) SetWriteDeadline(tm time.Time) error {
	t.writeDeadline.set(tm)
	return nil
}

// tunBioAddr is the type of address returned by [Conn]
type tunBioAddr struct {
	addr string
	net  string
}

var _ net.Addr = &tunBioAddr{}

// Network implements net.Addr. It returns the network
// for the underlying connection.
func (t *tunBioAddr) Network() string {
	return t.net
}

// String implements net.Addr
func (t *tunBioAddr) String() string {
	return t.addr
}
