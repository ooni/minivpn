package vpn

//
// Client initialization and public methods
//

import (
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

type DialFunc func(string, string) (net.Conn, error)

// tunnel holds state about the VPN tunnel that has longer duration than a
// given session.
type tunnel struct {
	ip  string
	mtu int
}

type vpnClient interface {
	Start() error
	Stop() error
	Dial() (net.Conn, error)
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
	if c.mux != nil {
		// TODO(ainghazal): test for multiple start/stop cycles
		return ErrAlreadyStarted
	}
	conn, err := c.Dial()
	if err != nil {
		return err
	}

	mux, err := newMuxerFromOptions(conn, c.Opts, c.tunnel)
	if err != nil {
		return err
	}

	err = mux.Handshake()
	if err != nil {
		return err
	}
	c.mux = mux
	return nil
}

// Stop stops the OpenVPN tunnel.
func (c *Client) Stop() error {
	if err := c.conn.Close(); err != nil {
		return err
	}
	c.mux = nil
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
	msg := fmt.Sprintf("Connecting to %s:%s with proto %s",
		c.Opts.Remote, c.Opts.Port, strings.ToUpper(proto))
	logger.Info(msg)
	conn, err := c.DialFn(proto, net.JoinHostPort(c.Opts.Remote, c.Opts.Port))

	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrDialError, err)
	}
	return conn, nil
}

// Write sends bytes into the tunnel.
func (c *Client) Write(b []byte) (int, error) {
	return c.mux.Write(b)
}

// Read reads bytes from the tunnel.
func (c *Client) Read(b []byte) (int, error) {
	if c.mux == nil {
		return 0, fmt.Errorf("%w:%s", errBadInput, "nil muxer")

	}
	return c.mux.Read(b)
}

// Close closes the tunnel connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// LocalLocalAddr returns the local address on the tunnel virtual device.
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
