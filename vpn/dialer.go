package vpn

import (
	"log"
	"net"
	"time"
)

// NewDialer returns a RawDialer configured with the given Options.
func NewRawDialer(opts *Options) *RawDialer {
	return &RawDialer{Options: opts}
}

// A RawDialer contains options for connecting to an OpenVPN endpoint.
type RawDialer struct {
	Options    *Options
	Timeout    time.Duration
	Deadline   time.Time
	KeepAlive  time.Duration
	NameServer string
	MTU        int
}

// Dial functions return an implementor of net.Conn that writes to and reads
// from the VPN tunnel. All the parameters passed to the Dial function are
// currently ignored.

// TODO probably need to register a handler for this connection
// or, perhaps easier, add destination in the conn struct

func (d *RawDialer) Dial() (net.PacketConn, error) {
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
	d.MTU = c.TunMTU()
	log.Println(">>> setting mtu", d.MTU)
	return PacketConn{cl: c, dc: dc}, nil
}

// Conn is a packet-oriented network connection using an OpenVPN tunnel. It
// implements the PacketConn interface.
type PacketConn struct {
	cl *Client
	dc chan []byte
}

// ReadFrom reads a packet from the connection,
// copying the payload into p. It returns the number of
// bytes copied into p and the return address that
// was on the packet.
func (p PacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	data := <-p.dc
	return copy(b, data), p.LocalAddr(), nil
}

// WriteTo writes a packet with payload p to addr.
// WriteTo can be made to time out and return an Error after a
// fixed time limit; see SetDeadline and SetWriteDeadline.
// On packet-oriented connections, write timeouts are rare.
func (p PacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	p.cl.SendData(b)
	return len(b), nil
}

// Close closes the connection.
func (p PacketConn) Close() error {
	p.cl.Stop()
	return nil
}

// LocalAddr returns the local network address, if known.
func (p PacketConn) LocalAddr() net.Addr {
	addr, _ := net.ResolveIPAddr("ip", p.cl.TunnelIP())
	return addr
}

// RemoteAddr returns the remote network address, if known.
func (p PacketConn) RemoteAddr() net.Addr {
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
func (p PacketConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
// A zero value for t means Read will not time out.
func (p PacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (p PacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}
