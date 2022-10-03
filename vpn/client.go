package vpn

//
// Client initialization and public methods
//

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

var (
	// ErrDialError is a generic error while dialing
	ErrDialError = errors.New("dial error")

	// ErrAlreadyStarted is returned when trying to start the tunnel more than once
	ErrAlreadyStarted = errors.New("tunnel already started")

	// ErrNotReady is returned when a Read/Write attempt is made before the tunnel is ready.
	ErrNotReady = errors.New("tunnel not ready")

	// ErrBadProxy is returned when attempting to use an unregistered proxy.
	ErrBadProxy = errors.New("unknown proxy")
)

const (
	// dialTimeoutInSeconds tells how long to wait on Dial
	dialTimeoutInSeconds = 10
)

// tunnelInfo holds state about the VPN tunnelInfo that has longer duration than a
// given session. This information is gathered at different stages:
// - during the handshake (mtu).
// - after server pushes config options(ip, gw).
type tunnelInfo struct {
	mtu    int
	ip     string
	gw     string
	peerID int
}

// vpnClient is a net.Conn that uses the VPN tunnel. It is a net.Conn with an
// additional `Start()` method.
type vpnClient interface {
	net.Conn
	Start(ctx context.Context) error
}

type dialContextFn func(context.Context, string, string) (net.Conn, error)

// DialerContext is anything that features a net.Dialer-like DialContext method.
type DialerContext interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// Client implements the OpenVPN protocol. A Client object satisfies the
// net.Conn interface. plus Start().
// The Read and Write operations send and receive bytes to and from the tunnel
// - they are writing to and reading from the OpenVPN Data channel, with the
// control channel being handled in the background.
// To Dial sockets through the Tunnel, you should use the NewTunDialer constructor,
// that accepts a Client object.
// Client is only intended to be directly instantiated by users that need a
// finer control of the protocol steps, or for the case in which you need the
// equivalent of raw sockets.
type Client struct {
	Opts   *Options
	Dialer DialerContext

	// If this channel is not nil, a series of Event* will be
	// sent to the channel. The user of the Client can set a
	// channel externally to subscribe to discrete transitions. A sufficiently
	// buffered-channel should be provided to avoid losing events (~10
	// events should do it).
	EventListener chan uint16

	Log Logger

	conn    net.Conn
	mux     vpnMuxer
	tunInfo *tunnelInfo

	// muxerFactoryFn allows to inject a different factory
	// for testing.
	muxerFactoryFn muxFactory

	startOnce sync.Once
	startErr  error
}

var _ net.Conn = &Client{}  // Ensure that we implement net.Conn
var _ vpnClient = &Client{} // Ensure that we implement vpnClient

// NewClientFromOptions returns a Client configured with the given Options.
func NewClientFromOptions(opt *Options) *Client {
	if opt == nil {
		return &Client{}
	}
	return &Client{
		Opts:    opt,
		tunInfo: &tunnelInfo{},
		Dialer:  &net.Dialer{},
	}
}

//
// observability
//

// emit sends the passed stage into any configured EventListener.
func (c *Client) emit(stage uint16) {
	select {
	case c.EventListener <- stage:
	default:
		// don't deliver
	}
}

// Start starts the OpenVPN tunnel.
func (c *Client) Start(ctx context.Context) error {
	c.startOnce.Do(func() {
		c.startErr = c.start(ctx)
	})
	return c.startErr
}

func (c *Client) start(ctx context.Context) error {
	c.emit(EventReady)

	// we hardcode a lesser-lived context for dial step for now.
	dialCtx, cancel := context.WithDeadline(
		context.Background(),
		time.Now().Add(dialTimeoutInSeconds*time.Second))
	defer cancel()
	conn, err := c.dial(dialCtx)
	if err != nil {
		return err
	}

	c.emit(EventDialDone)

	muxFactory := c.muxerFactory()
	mux, err := muxFactory(conn, c.Opts, c.tunInfo)
	if err != nil {
		conn.Close()
		return err
	}

	mux.SetEventListener(c.EventListener)

	c.emit(EventHandshake)

	handshakeCtx, handshakeCancel := context.WithDeadline(
		ctx,
		time.Now().Add(30*time.Second))
	defer handshakeCancel()

	err = mux.Handshake(handshakeCtx)
	if err != nil {
		conn.Close()
		return err
	}

	c.emit(EventHandshakeDone)

	c.conn = conn
	c.mux = mux
	return nil
}

// muxerFactory returns the default muxer Factory, or any other one that has
// been injected into the `muxerFactoryFn` private field in Client for testing.
func (c *Client) muxerFactory() muxFactory {
	muxFactory := newMuxerFromOptions
	if c.muxerFactoryFn == nil {
		return muxFactory
	}
	return c.muxerFactoryFn
}

// dial opens a TCP/UDP socket against the remote, and creates an internal
// data channel. It is the second step in an OpenVPN connection (out of five).
// (In UDP mode no network connection is done at this step).
func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	if c.Opts == nil {
		return nil, fmt.Errorf("%w:%s", errBadInput, "nil options")

	}
	var proto string
	switch c.Opts.Proto {
	case UDPMode:
		proto = protoUDP.String()
	case TCPMode:
		proto = protoTCP.String()
	default:
		return nil, fmt.Errorf("%w: unknown proto %d", errBadInput, c.Opts.Proto)

	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		msg := fmt.Sprintf("Connecting to %s:%s with proto %s",
			c.Opts.Remote, c.Opts.Port, strings.ToUpper(proto))
		logger.Info(msg)

		conn, err := c.Dialer.DialContext(ctx, proto, net.JoinHostPort(c.Opts.Remote, c.Opts.Port))
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrDialError, err)
		}
		return conn, nil
	}
}

// Write sends bytes into the tunnel.
func (c *Client) Write(b []byte) (int, error) {
	return c.mux.Write(b)
}

// Read reads bytes from the tunnel.
func (c *Client) Read(b []byte) (int, error) {
	if c.mux == nil {
		return 0, ErrNotReady

	}
	return c.mux.Read(b)
}

// Close closes the tunnel connection.
func (c *Client) Close() error {
	if c.mux != nil {
		c.mux.Stop()
	}
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// LocalAddr returns the local address on the tunnel virtual device, if known.
// In case the Addr is not known, a zero-value net.Addr will be returned.
func (c *Client) LocalAddr() net.Addr {
	addr := &net.IPAddr{}
	if c.tunInfo != nil {
		if ip := net.ParseIP(c.tunInfo.ip); ip != nil {
			addr.IP = ip
		}
	}
	return addr
}

// RemoteAddr returns the address of the tun interface of the tunnel gateway,
// if known. In case the Addr is not known, a zero-value net.Addr will be returned.
func (c *Client) RemoteAddr() net.Addr {
	addr := &net.IPAddr{}
	if c.tunInfo != nil {
		if ip := net.ParseIP(c.tunInfo.gw); ip != nil {
			addr.IP = ip
		}
	}
	return addr
}

func (c *Client) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *Client) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *Client) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
