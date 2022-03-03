package vpn

// This file contains dialer types and functions that allow transparent use of
// an OpenVPN connection.

import (
	"log"
	"net"
	"time"

	"golang.zx2c4.com/go118/netip"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var (
	openDNSPrimary   = "208.67.222.222"
	openDNSSecondary = "208.67.220.220"
)

// A Dialer contains options for obtaining a network connection tunneled
// through an OpenVPN endpoint.
type Dialer struct {
	ns1 string
	ns2 string
	raw *RawDialer
}

// NewDialer creates a new Dialer with the default nameservers (OpenDNS).
func NewDialer(raw *RawDialer) Dialer {
	return Dialer{raw: raw, ns1: openDNSPrimary, ns2: openDNSSecondary}
}

// NewDialerNewDialerWithNameservers creates a new Dialer with the passed nameservers.
// You probably want to pass the nameservers for your own VPN service here.
func NewDialerWithNameservers(raw *RawDialer, ns1, ns2 string) Dialer {
	return Dialer{raw: raw, ns1: ns1, ns2: ns2}
}

// Dial connects to the address on the named network, via the OpenVPN endpoint
// that is configured in the dialer.
//
// The return value implements the net.Conn interface, but it is a socket created
// on a virtual device, using gVisor userspace network stack. This means that the
// kernel only sees UDP packets with an encrypted payload.
//
// The addresses are resolved via the OpenVPN tunnel too, and against the nameservers
// configured in the dialer. This feature uses wireguard's little custom DNS client
// implementation.
//
// Known networks are "tcp", "tcp4" (IPv4-only), "tcp6" (IPv6-only),
// "udp", "udp4" (IPv4-only), "udp6" (IPv6-only), "ping4", "ping6".
func (d Dialer) Dial(network, address string) (net.Conn, error) {
	raw, err := d.raw.Dial()
	if err != nil {
		return nil, err
	}
	localIP := raw.LocalAddr().String()

	// create a virtual device in userspace, courtesy of wireguard-go
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(localIP)},
		[]netip.Addr{
			netip.MustParseAddr(d.ns1),
			netip.MustParseAddr(d.ns2)},
		d.raw.MTU)
	if err != nil {
		return nil, err
	}

	// connect the virtual device to our openvpn tunnel
	dev := &device{tun, raw}
	dev.Up()

	return tnet.Dial(network, address)
}

// DialTimeout acts like Dial but takes a timeout.
func (d Dialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	conn, err := d.Dial(network, address)
	if err != nil {
		return nil, err
	}
	conn.SetReadDeadline(time.Now().Add(timeout))
	return conn, nil
}

// device contains the two halves of the tunnel that we are connecting in our
// toy implementation: the virtual tun device that is handled by netstack, and
// the raw PacketConn that writes and reads to sockets provided by the kernel.
type device struct {
	tun tun.Device
	raw net.PacketConn
}

// Up spawns two goroutines that communicate the two halves of a device.
func (d *device) Up() {
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := d.tun.Read(b, 0) // zero offset
			if err != nil {
				log.Println("tun read error:", err)
				break
			}
			d.raw.WriteTo(b[0:n], nil)
		}
	}()
	go func() {
		b := make([]byte, 4096)
		for {
			n, _, err := d.raw.ReadFrom(b)
			if err != nil {
				log.Println("raw read error:", err)
				break
			}
			d.tun.Write(b[0:n], 0) // zero offset
		}
	}()
}

// RawDialer contains options for connecting to an OpenVPN endpoint.
type RawDialer struct {
	Options    *Options
	NameServer string
	MTU        int
}

// NewRawDialer returns a RawDialer configured with the given Options.
func NewRawDialer(opts *Options) *RawDialer {
	return &RawDialer{Options: opts}
}

// Dial returns a PacketConn that writes to and reads from the VPN tunnel.
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
	done := make(chan bool) // TODO use a context instead
	c.WaitUntil(done)
	return packetConn{cl: c, dc: dc}, nil
}

// packetConn is a packet-oriented network connection using an OpenVPN tunnel. It
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

// dummy implementations, I'm not sure how much sense it makes to map the
// expected semantics.

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
