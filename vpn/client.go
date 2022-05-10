package vpn

//
// Client initialization and public methods
//

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

var (
	handshakeTimeout    = 30
	handshakeTimeoutEnv = "HANDSHAKE_TIMEOUT"
)

var logger Logger

// NewClientFromSettings returns a Client configured with the given Options.
func NewClientFromSettings(opt *Options) *Client {
	t := handshakeTimeout
	tenv := os.Getenv(handshakeTimeoutEnv)
	if tenv != "" {
		ti, err := strconv.Atoi(tenv)
		if err == nil {
			t = ti
		} else {
			log.Println("Cannot set timeot from env:", os.Getenv(handshakeTimeoutEnv))
		}
	}
	if opt.Log != nil {
		logger = opt.Log
	}
	return &Client{
		Opts:             opt,
		tunnel:           &tunnel{},
		DialFn:           net.Dial,
		HandshakeTimeout: t,
	}
}

type DialFunc func(string, string) (net.Conn, error)

// Client implements the OpenVPN protocol. If you're just interested in writing
// to and reading from the tunnel you should use the dialer methods instead.
// This type is only intended to be instantiated by users that need a finer control
// of the protocol steps (i.e., you want to be sure that you are only calling
// the handshake, etc.)
type Client struct {
	Opts   *Options
	DialFn DialFunc

	mux    *muxer
	data   *data
	tunnel *tunnel

	conn net.Conn

	Log Logger

	// TODO where does this belong?
	HandshakeTimeout int
}

type tunnel struct {
	ip  string
	mtu int
}

// Run starts the OpenVPN tunnel.
func (c *Client) Run() error {
	conn, err := c.Dial()
	if err != nil {
		return err
	}

	mux, err := newMuxerFromOptions(conn, c.Opts)
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

// Dial opens a TCP/UDP socket against the remote, and creates an internal
// data channel. It is the second step in an OpenVPN connection (out of five).
// (In UDP mode no network connection is done at this step).
func (c *Client) Dial() (net.Conn, error) {
	proto := protoUDP.String()
	if isTCP(c.Opts.Proto) {
		proto = protoTCP.String()
	}
	msg := fmt.Sprintf("Connecting to %s:%s with proto %s",
		c.Opts.Remote, c.Opts.Port, strings.ToUpper(proto))
	logger.Info(msg)
	conn, err := c.DialFn(proto, net.JoinHostPort(c.Opts.Remote, c.Opts.Port))

	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrDialError, err)
	}
	return conn, nil
}

// Write sends bytes into the tunnel.
func (c *Client) Write(b []byte) (int, error) {
	return c.mux.Write(b)
}

// Read reads bytes from the tunnel.
func (c *Client) Read(b []byte) (int, error) {
	return c.mux.Read(b)
}

// Close closes the tunnel connection.
//func (c *Client) Close() {
//	c.conn.Close()
//}

// TunnelIP returns the local IP that the server assigned us.
func (m *muxer) TunnelIP() string {
	return m.tunnel.ip
}

// TunMTU returns the tun-mtu value that the remote advertises.
func (m *muxer) TunMTU() int {
	return m.tunnel.mtu
}

// Logger is compatible with github.com/apex/log
type Logger interface {
	// Debug emits a debug message.
	Debug(msg string)

	// Debugf formats and emits a debug message.
	Debugf(format string, v ...interface{})

	// ... ?
	Error(msg string)

	// ... ?
	Errorf(format string, v ...interface{})

	// Info emits an informational message.
	Info(msg string)

	// Infof formats and emits an informational message.
	Infof(format string, v ...interface{})

	// Warn emits a warning message.
	Warn(msg string)

	// Warnf formats and emits a warning message.
	Warnf(format string, v ...interface{})
}
