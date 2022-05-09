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

// NewClientFromSettings returns a Client configured with the given Options.
func NewClientFromSettings(o *Options) *Client {
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
	return &Client{
		Opts:             o,
		HandshakeTimeout: t,
		tunnel:           &tunnel{},
		DialFn:           net.Dial,
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

	// TODO does this belong here?
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

	// TODO newMuxerFromOptions?
	mux := &muxer{conn: conn}
	err = mux.Init(c.Opts)
	if err != nil {
		return err
	}

	err = mux.Handshake()
	if err != nil {
		return err
	}
	log.Println("VPN handshake done.")
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
	log.Printf("Connecting to %s:%s with proto %s\n", c.Opts.Remote, c.Opts.Port, strings.ToUpper(proto))
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
