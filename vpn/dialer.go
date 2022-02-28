package vpn

import (
	"net"
	"time"
)

// NewDialer returns a Dialer configured with the given Options.
func NewDialer(opts *Options) *Dialer {
	return &Dialer{Options: opts}
}

// A Dialer contains options for connecting to an OpenVPN endpoint.
type Dialer struct {
	Options   *Options
	Timeout   time.Duration
	Deadline  time.Time
	KeepAlive time.Duration
	// TODO can map to kepalive openvpn option
}

func (d *Dialer) Dial() (net.PacketConn, error) {
	// TODO catch error here
	c := NewClientFromSettings(d.Options)
	// TODO unwrap these errors and classify them in connection stages
	err := c.Run()
	if err != nil {
		return nil, err
	}
	dc := c.DataChannel()
	done := make(chan bool)
	c.WaitUntil(done)
	return Conn{cl: c, dc: dc}, nil
}

// Conn is a packet-oriented network connection using an OpenVPN tunnel. It
// implements the PacketConn interface.
type Conn struct {
	cl *Client
	dc chan []byte
}

// ReadFrom reads a packet from the connection,
// copying the payload into p. It returns the number of
// bytes copied into p and the return address that
// was on the packet.
func (c Conn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	data := <-c.dc
	for i, v := range data {
		p[i] = v
	}
	return len(data), nil, err
}

// WriteTo writes a packet with payload p to addr.
// WriteTo can be made to time out and return an Error after a
// fixed time limit; see SetDeadline and SetWriteDeadline.
// On packet-oriented connections, write timeouts are rare.
func (c Conn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.cl.SendData(p)
	return len(p), nil
}

/* -------------------------------------------------------------------------------------------*/
/* TODO this is from the net.Conn interface, I don't know if it makes sense to implement this */

// Read reads data from the connection.
// Read can be made to time out and return an error after a fixed
// time limit; see SetDeadline and SetReadDeadline.
func (c Conn) Read(b []byte) (n int, err error) {
	return 0, nil
}

// Write writes data to the connection.
// Write can be made to time out and return an error after a fixed
// time limit; see SetDeadline and SetWriteDeadline.
func (c Conn) Write(b []byte) (n int, err error) {
	return 0, nil
}

/* ------------------------------------------------------------------------------------------ */

// Close closes the connection.
func (c Conn) Close() error {
	c.cl.Stop()
	return nil
}

// LocalAddr returns the local network address, if known.
func (c Conn) LocalAddr() net.Addr {
	addr, _ := net.ResolveIPAddr("ip", c.cl.TunnelIP())
	return addr
}

// RemoteAddr returns the remote network address, if known.
func (c Conn) RemoteAddr() net.Addr {
	return nil
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations
// fail instead of blocking. The deadline applies to all future
// and pending I/O, not just the immediately following call to
// Read or Write. After a deadline has been exceeded, the
// connection can be refreshed by setting a deadline in the future.
//
// If the deadline is exceeded a call to Read or Write or to other
// I/O methods will return an error that wraps os.ErrDeadlineExceeded.
// This can be tested using errors.Is(err, os.ErrDeadlineExceeded).
// The error's Timeout method will return true, but note that there
// are other possible errors for which the Timeout method will
// return true even if the deadline has not been exceeded.
//
// An idle timeout can be implemented by repeatedly extending
// the deadline after successful Read or Write calls.
//
// A zero value for t means I/O operations will not time out.
func (c Conn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
// A zero value for t means Read will not time out.
func (c Conn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (c Conn) SetWriteDeadline(t time.Time) error {
	return nil
}
