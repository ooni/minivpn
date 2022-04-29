package vpn

// This file contains dialer types and functions that allow transparent use of
// an OpenVPN connection.

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"golang.zx2c4.com/go118/netip"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var (
	openDNSPrimary   = "208.67.222.222"
	openDNSSecondary = "208.67.220.220"
)

type network struct {
	up   bool
	tnet *netstack.Net
	mu   sync.Mutex
}

func (n *network) init(t *netstack.Net) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.tnet = t
	n.up = true
}

func (n *network) isUp() bool {
	return n.up
}

// A Dialer contains options for obtaining a network connection tunneled
// through an OpenVPN endpoint.
type Dialer struct {
	ns1 string
	ns2 string
	raw *RawDialer
	net *network
	// TODO perhaps rename to TransportDialFunc?? I'm afraid this is confusing terminology as-is.
	DialFn DialFunc
}

// NewDialer creates a new Dialer with the default nameservers (OpenDNS).
func NewDialer(raw *RawDialer) Dialer {
	return Dialer{raw: raw, ns1: openDNSPrimary, ns2: openDNSSecondary, net: &network{}}
}

// NewDialerWithNameservers creates a new Dialer with the passed nameservers.
// You probably want to pass the nameservers for your own VPN service here.
func NewDialerWithNameservers(raw *RawDialer, ns1, ns2 string) Dialer {
	return Dialer{raw: raw, ns1: ns1, ns2: ns2, net: &network{}}
}

// NewDialerFromOptions creates a new Dialer directly from an Options object.
func NewDialerFromOptions(o *Options) Dialer {
	raw := NewRawDialer(o)
	return Dialer{raw: raw, ns1: openDNSPrimary, ns2: openDNSSecondary, net: &network{}}
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
	if d.net.isUp() {
		return d.net.tnet.Dial(network, address)
	}
	tnet, err := d.createNetTUN()
	if err != nil {
		return nil, err
	}
	d.net.init(tnet)
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

// DialContext connects to the address on the named network using
// the provided context.
func (d Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.net.isUp() {
		return d.net.tnet.DialContext(ctx, network, address)
	}
	tnet, err := d.createNetTUN()
	if err != nil {
		return nil, err
	}
	d.net.init(tnet)
	return tnet.DialContext(ctx, network, address)
}

func (d Dialer) createNetTUN() (*netstack.Net, error) {
	if d.DialFn != nil {
		d.raw.dialFn = d.DialFn
	}
	pc, err := d.raw.Dial()
	if err != nil {
		return nil, err
	}
	localIP := pc.LocalAddr().String()

	// create a virtual device in userspace, courtesy of wireguard-go
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(localIP)},
		[]netip.Addr{
			netip.MustParseAddr(d.ns1),
			netip.MustParseAddr(d.ns2)},
		d.raw.MTU-100) // BUG(ainghazal): cannot use the tun-mtu that the remote advertises
	if err != nil {
		return nil, err
	}

	// connect the virtual device to our openvpn tunnel
	dev := &device{tun, pc}
	dev.Up()

	return tnet, nil
}

// device contains the two halves of the tunnel that we are connecting in our
// toy implementation: the virtual tun device that is handled by netstack, and
// the raw PacketConn that writes and reads to sockets provided by the kernel.
type device struct {
	tun tun.Device
	pc  net.PacketConn
}

// Up spawns two goroutines that communicate the two halves of a device.
func (d *device) Up() {
	go func() {
		b := make([]byte, 40960)
		for {
			n, err := d.tun.Read(b, 0) // zero offset
			if err != nil {
				log.Println("tun read error:", err)
				break
			}
			d.pc.WriteTo(b[0:n], nil)
		}
	}()
	go func() {
		b := make([]byte, 40960)
		for {
			n, _, err := d.pc.ReadFrom(b)
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
	Options *Options
	MTU     int
	c       *Client
	// dialFn will be used by the Client to establish the tunnel.
	// If not initialized, it defaults to net.Dial.
	// If a different DialFunc is passed via the higher-level Dialer, that
	// will be used instead.
	dialFn DialFunc
}

// NewRawDialer returns a RawDialer configured with the given Options.
func NewRawDialer(opts *Options) *RawDialer {
	return &RawDialer{Options: opts}
}

// Dial returns a PacketConn that writes to and reads from the VPN tunnel.
func (d *RawDialer) Dial() (net.PacketConn, error) {
	if d.c == nil {
		// TODO catch error here
		c := NewClientFromSettings(d.Options)
		if d.dialFn != nil {
			c.DialFn = d.dialFn
		}
		d.c = c
		// TODO unwrap these errors and classify them in connection stages
		err := d.c.Run()
		if err != nil {
			return nil, err
		}
		d.MTU = d.c.TunMTU()
		done := make(chan bool) // TODO use a context instead
		c.WaitUntil(done)
	}
	return packetConn{cl: d.c, dc: d.c.DataChannel()}, nil
}

// packetConn is a packet-oriented network connection using an OpenVPN tunnel. It
// implements the PacketConn interface.
type packetConn struct {
	cl *Client
	dc chan []byte
}

// ReadFrom reads a packet from the connection, copying the payload into b. It
// returns the number of bytes copied into b and the return address that
// was on the packet.
func (p packetConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	data := <-p.dc
	return copy(b, data), p.LocalAddr(), nil
}

// WriteTo writes a packet with payload b to addr.
func (p packetConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	p.cl.Write(b)
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
