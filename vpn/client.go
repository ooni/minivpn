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
	"time"
)

var (
	// ErrDialError is a generic error while dialing
	ErrDialError = errors.New("dial error")

	// ErrAlreadyStarted is returned when trying to start the tunnel more than once
	ErrAlreadyStarted = errors.New("tunnel already started")
)

// tunnel holds state about the VPN tunnel that has longer duration than a
// given session.
type tunnel struct {
	ip  string
	mtu int
}

// vpnClient has a Start and a Dial method.
type vpnClient interface {
	Start(ctx context.Context) error
	Dial(ctx context.Context) (net.Conn, error)
}

type DialContextFn func(context.Context, string, string) (net.Conn, error)

// DialerContext is anything that features a net.Dialer-like DialContext method.
type DialerContext interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// Client implements the OpenVPN protocol. If you're just interested in writing
// to and reading from the tunnel you should use the dialer methods instead.
// This type is only intended to be instantiated by users that need a finer control
// of the protocol steps (i.e., you want to be sure that you are only calling
// the handshake, etc.)
type Client struct {
	Opts   *Options
	Dialer DialerContext

	conn   net.Conn
	mux    vpnMuxer
	tunnel *tunnel

	Log Logger

	muxerFactoryFn muxFactory
}

var _ net.Conn = &Client{}  // Ensure that we implement net.Conn
var _ vpnClient = &Client{} // Ensure that we implement vpnClient

// NewClientFromOptions returns a Client configured with the given Options.
func NewClientFromOptions(opt *Options) vpnClient {
	if opt == nil {
		return &Client{}
	}
	if opt.Log != nil {
		logger = opt.Log
	}
	return &Client{
		Opts:   opt,
		tunnel: &tunnel{},
		Dialer: &net.Dialer{},
	}
}

// Start starts the OpenVPN tunnel.
func (c *Client) Start(ctx context.Context) error {
	conn, err := c.Dial(ctx)
	if err != nil {
		return err
	}
	c.conn = conn

	if c.mux == nil {
		muxFactory := c.muxerFactory()
		mux, err := muxFactory(conn, c.Opts, c.tunnel)
		if err != nil {
			return err
		}
		err = mux.Handshake(ctx)
		if err != nil {
			return err
		}
		c.mux = mux
	}
	return nil
}

// muxerFactory returns the default muxer Factory, or any other one that has been injected into the `muxerFactoryFn` private field in Client for testing.
func (c *Client) muxerFactory() muxFactory {
	muxFactory := newMuxerFromOptions
	if c.muxerFactoryFn == nil {
		return muxFactory
	}
	return c.muxerFactoryFn
}

// Dial opens a TCP/UDP socket against the remote, and creates an internal
// data channel. It is the second step in an OpenVPN connection (out of five).
// (In UDP mode no network connection is done at this step).
func (c *Client) Dial(ctx context.Context) (net.Conn, error) {
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
		return 0, fmt.Errorf("%w: %s", errBadInput, "nil muxer")

	}
	return c.mux.Read(b)
}

// Close closes the tunnel connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// LocalAddr returns the local address on the tunnel virtual device.
func (c *Client) LocalAddr() net.Addr {
	if c.tunnel == nil {
		addr, _ := net.ResolveIPAddr("ip", "")
		return addr
	}
	addr, _ := net.ResolveIPAddr("ip", c.tunnel.ip)
	return addr
}

// TODO(ainghazal): should get the remote _tunnel_ ip addr somehow
func (c *Client) RemoteAddr() net.Addr {
	logger.Errorf("client.RemoteAddr() not implemented")
	return nil
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
