package tun

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/networkio"
	"github.com/ooni/minivpn/internal/session"
)

var (
	// default TLS handshake timeout, in seconds.
	tlsHandshakeTimeoutSeconds = 60
)

// StartTUN initializes and starts the TUN device over the vpn.
// If the passed context expires before the TUN device is ready,
func StartTUN(ctx context.Context, conn networkio.FramingConn, config *model.Config) (*TUN, error) {
	// create a session
	sessionManager, err := session.NewManager(config.Logger())
	if err != nil {
		return nil, err
	}

	// create the TUN that will OWN the connection
	tunnel := newTUN(config.Logger(), conn, sessionManager)

	// start all the workers
	workers := startWorkers(config, conn, sessionManager, tunnel)
	tunnel.whenDone(func() {
		workers.StartShutdown()
		workers.WaitWorkersShutdown()
	})

	tlsTimeout := time.NewTimer(time.Duration(tlsHandshakeTimeoutSeconds) * time.Second)

	// Await for the signal from the session manager to tell us we're ready to start accepting data.
	// In practice, this means that we already have a valid TunnelInfo at this point
	// (i.e., three way handshake has completed, and we have valid keys).

	select {
	case <-sessionManager.Ready:
		return tunnel, nil
	case <-tlsTimeout.C:
		defer func() {
			config.Logger().Info("tls timeout")
			tunnel.Close()
		}()
		return nil, errors.New("tls timeout")
	case <-ctx.Done():
		defer func() {
			tunnel.Close()
		}()
		return nil, ctx.Err()
	}
}

// TUN allows to use channels to read and write. It also OWNS the underlying connection.
// TUN implements net.Conn
type TUN struct {
	// ensure idempotency.
	closeOnce sync.Once

	// conn is the underlying connection.
	conn networkio.FramingConn

	// hangup is used to let methods know the connection is closed.
	hangup chan any

	// logger implements model.Logger
	logger model.Logger

	// network is the underlying network for the passed [networkio.FramingConn].
	network string

	// used to buffer reads from above.
	readBuffer *bytes.Buffer

	// readDeadline is used to set the read deadline.
	readDeadline tunDeadline

	// session is the session manager
	session *session.Manager

	// tunDown moves bytes down to the data channel.
	tunDown chan []byte

	// tunUp moves bytes up from the data channel.
	tunUp chan []byte

	// callback to be executed on shutdown.
	whenDoneFn func()

	// writeDeadline is used to set the write deadline.
	writeDeadline tunDeadline
}

// newTUN creates a new TUN.
// This function TAKES OWNERSHIP of the conn.
func newTUN(logger model.Logger, conn networkio.FramingConn, session *session.Manager) *TUN {
	return &TUN{
		closeOnce:    sync.Once{},
		conn:         conn,
		hangup:       make(chan any),
		logger:       logger,
		network:      conn.LocalAddr().Network(),
		readBuffer:   &bytes.Buffer{},
		readDeadline: makeTUNDeadline(),
		session:      session,
		tunDown:      make(chan []byte),
		tunUp:        make(chan []byte),
		// this function is explicitely set empty so that we can safely use a callback even if not set.
		whenDoneFn:    func() {},
		writeDeadline: makeTUNDeadline(),
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
	for {
		count, _ := t.readBuffer.Read(data)
		if count > 0 {
			// log.Printf("[tunbio] received %d bytes", len(data))
			return count, nil
		}
		if isClosedChan(t.readDeadline.wait()) {
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
	if isClosedChan(t.writeDeadline.wait()) {
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
	ip := t.session.TunnelInfo().IP
	return &tunBioAddr{ip, t.network}
}

func (t *TUN) RemoteAddr() net.Addr {
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

// tunBioAddr is the type of address returned by [*TUN]
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

func (t *TUN) NetMask() net.IPMask {
	return net.IPMask(net.ParseIP(t.session.TunnelInfo().NetMask))
}
