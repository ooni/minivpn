package vpn

import (
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
	NameServer string
	MTU        int
}

// Dial return a PacketConn that writes to and reads from the VPN tunnel.
func (d *RawDialer) Dial() (net.PacketConn, error) {
	// TODO catch error here
	c := NewClientFromSettings(d.Options)
	// TODO unwrap these errors and classify them in connection stages
	err := c.Run()
	if err != nil {
		return nil, err
	}
	d.MTU = c.TunMTU()
	dc := c.DataChannel()
	done := make(chan bool)
	c.WaitUntil(done)
	return packetConn{cl: c, dc: dc}, nil
}

// Conn is a packet-oriented network connection using an OpenVPN tunnel. It
// implements the PacketConn interface.
type packetConn struct {
	cl *Client
	dc chan []byte
}

// ReadFrom reads a packet from the connection, copying the payload into p. It
// returns the number of bytes copied into p and the return address that
// was on the packet.
func (p packetConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	data := <-p.dc
	return copy(b, data), p.LocalAddr(), nil
}

// WriteTo writes a packet with payload p to addr.
func (p packetConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	p.cl.SendData(b)
	return len(b), nil
}

// Close closes the connection.
func (p packetConn) Close() error {
	p.cl.Stop()
	return nil
}

// LocalAddr returns the local network address, if known.
func (p packetConn) LocalAddr() net.Addr {
	addr, _ := net.ResolveIPAddr("ip", p.cl.TunnelIP())
	return addr
}

// RemoteAddr returns the remote network address, if known.
func (p packetConn) RemoteAddr() net.Addr {
	return nil
}

func (p packetConn) SetDeadline(t time.Time) error {
	return nil
}

func (p packetConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (p packetConn) SetWriteDeadline(t time.Time) error {
	return nil
}
