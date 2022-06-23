package vpn

//
// Client initialization and public methods
//

import (
	"context"
	"errors"
	"fmt"
	"log"
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

type DialFunc func(string, string) (net.Conn, error)

// tunnel holds state about the VPN tunnel that has longer duration than a
// given session.
type tunnel struct {
	ip  string
	mtu int
}

type vpnClient interface {
	Start() error
	Dial() (net.Conn, error)
	WithContext(context.Context) vpnClient
}

// Client implements the OpenVPN protocol. If you're just interested in writing
// to and reading from the tunnel you should use the dialer methods instead.
// This type is only intended to be instantiated by users that need a finer control
// of the protocol steps (i.e., you want to be sure that you are only calling
// the handshake, etc.)
type Client struct {
	Opts   *Options
	DialFn DialFunc

	conn   net.Conn
	mux    vpnMuxer
	tunnel *tunnel

	// ctx is the client context.
	ctx context.Context

	Log Logger
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
		DialFn: net.Dial,
	}
}

// Start starts the OpenVPN tunnel.
func (c *Client) Start() error {
	conn, err := c.Dial()
	if err != nil {
		return err
	}
	c.conn = conn

	mux, err := newMuxerFromOptions(conn, c.Opts, c.tunnel)
	if err != nil {
		return err
	}
	mux = mux.WithContext(c.Context())

	err = mux.Handshake()
	if err != nil {
		return err
	}
	c.mux = mux
	return nil
}

// Dial opens a TCP/UDP socket against the remote, and creates an internal
// data channel. It is the second step in an OpenVPN connection (out of five).
// (In UDP mode no network connection is done at this step).
func (c *Client) Dial() (net.Conn, error) {
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

	ctx := c.Context()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		msg := fmt.Sprintf("Connecting to %s:%s with proto %s",
			c.Opts.Remote, c.Opts.Port, strings.ToUpper(proto))
		logger.Info(msg)

		// FIXME change DialFn
		// TODO honor DialFn -- but this is not working for UDP sockets.
		//conn, err := c.DialFn(proto, net.JoinHostPort(c.Opts.Remote, c.Opts.Port))
		var d net.Dialer
		conn, err := d.DialContext(ctx, proto, net.JoinHostPort(c.Opts.Remote, c.Opts.Port))

		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrDialError, err)
		}
		return conn, nil
	}
}

// WithContext returns a shallow copy of c with its context changed
// to ctx. The provided ctx must be non-nil.
func (c *Client) WithContext(ctx context.Context) vpnClient {
	if ctx == nil {
		panic("nil context")
	}
	c2 := new(Client)
	*c2 = *c
	c2.ctx = ctx
	return c2
}

// Context returns the client context. To change the context, use WithContext.
func (c *Client) Context() context.Context {
	if c.ctx != nil {
		return c.ctx
	}
	return context.Background()
}

// Write sends bytes into the tunnel.
func (c *Client) Write(b []byte) (int, error) {
	ctx := c.Context()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
		return c.mux.Write(b)
	}
}

// Read reads bytes from the tunnel.
func (c *Client) Read(b []byte) (int, error) {
	if c.mux == nil {
		return 0, fmt.Errorf("%w:%s", errBadInput, "nil muxer")

	}
	ctx := c.Context()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
		return c.mux.Read(b)
	}
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
	if c.conn == nil {
		log.Println("CONN IS NIL")

	}
	return c.conn.SetReadDeadline(t)
}

func (c *Client) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
