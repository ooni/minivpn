package vpn

// This file contains dialer types and functions that allow transparent use of
// an OpenVPN connection.

import (
	"context"
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

// A TunDialer contains options for obtaining a network connection tunneled
// through an OpenVPN endpoint. It uses a userspace gVisor virtual device over
// the raw VPN tunnel.
type TunDialer struct {
	DialFn DialFunc
	raw    *RawDialer
	ns1    string
	ns2    string
}

// NewTunDialer creates a new Dialer with the default nameservers (OpenDNS).
func NewTunDialer(raw *RawDialer) TunDialer {
	td := TunDialer{
		raw: raw,
		ns1: openDNSPrimary,
		ns2: openDNSSecondary,
	}
	return td
}

// NewDialerWithNameservers creates a new Dialer with the passed nameservers.
// You probably want to pass the nameservers for your own VPN service here.
func NewTunDialerWithNameservers(raw *RawDialer, ns1, ns2 string) TunDialer {
	td := TunDialer{
		raw: raw,
		ns1: ns1,
		ns2: ns2,
	}
	return td
}

// NewDialerFromOptions creates a new Dialer directly from an Options object.
func NewTunDialerFromOptions(opt *Options) TunDialer {
	raw := NewRawDialer(opt)
	td := TunDialer{
		raw: raw,
		ns1: openDNSPrimary,
		ns2: openDNSSecondary,
	}
	return td
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
func (td TunDialer) Dial(network, address string) (net.Conn, error) {
	tnet, err := td.createNetTUN()
	if err != nil {
		return nil, err
	}
	return tnet.Dial(network, address)
}

// DialTimeout acts like Dial but takes a timeout.
func (td TunDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	conn, err := td.Dial(network, address)
	if err != nil {
		return nil, err
	}
	err = conn.SetReadDeadline(time.Now().Add(timeout))
	return conn, err
}

// DialContext connects to the address on the named network using
// the provided context.
func (td TunDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	tnet, err := td.createNetTUN()
	if err != nil {
		return nil, err
	}
	return tnet.DialContext(ctx, network, address)
}

func (td TunDialer) createNetTUN() (*netstack.Net, error) {
	if td.DialFn != nil {
		td.raw.dialFn = td.DialFn
	}

	client, err := td.raw.dial()
	if err != nil {
		return nil, err
	}
	localIP := client.LocalAddr().String()

	// create a virtual device in userspace, courtesy of wireguard-go
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(localIP)},
		[]netip.Addr{
			netip.MustParseAddr(td.ns1),
			netip.MustParseAddr(td.ns2)},
		client.tunnel.mtu-100,
	)
	// BUG(ainghazal): we cannot use the tun-mtu that the remote
	// advertises, so we substract a "safety" margin for now.

	if err != nil {
		return nil, err
	}

	// connect the virtual device to our openvpn tunnel
	dev := &device{tun, client}
	dev.Up()

	return tnet, nil
}

// device contains the two halves of the tunnel that we are connecting in our
// toy implementation: the virtual tun device that is handled by netstack, and
// the vpn.Client (that satisfies a net.Conn) that writes and reads to sockets
// provided by the kernel.
type device struct {
	tun tun.Device
	vpn net.Conn
}

// Up spawns two goroutines that communicate the two halves of a device.
func (d *device) Up() {
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := d.tun.Read(b, 0) // zero offset
			if err != nil {
				logger.Errorf("tun read error: %v", err)
				break
			}
			_, err = d.vpn.Write(b[0:n])
			if err != nil {
				logger.Errorf("vpn write error: %v", err)
				break
			}

		}
	}()
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := d.vpn.Read(b)
			if err != nil {
				logger.Errorf("vpn read error: %v", err)
				break
			}
			_, err = d.tun.Write(b[0:n], 0) // zero offset
			if err != nil {
				logger.Errorf("tun write error: %v", err)
				break
			}
		}
	}()
}

type RawDialer struct {
	Options *Options
	// dialFn is the on-the-wire dial function that will be passed to the
	// OpenVPN client.
	dialFn DialFunc
}

func NewRawDialer(opts *Options) *RawDialer {
	return &RawDialer{Options: opts}
}

// Dial returns a net.Conn that writes to and reads (raw packets) from the VPN
// tunnel.
func (d *RawDialer) Dial() (net.Conn, error) {
	return d.dial()
}

// dial returns a vpn Client (that implements net.Conn). We do this because in
// the TunDialer that access this we need to access some private fields from
// the Client implementation.
func (d *RawDialer) dial() (*Client, error) {
	client, err := clientFactoryFn(d.Options, d.dialFn)
	return client, err
}

func clientFactory(opt *Options, dialFn DialFunc) (*Client, error) {
	client := NewClientFromOptions(opt)
	if dialFn != nil {
		client.DialFn = dialFn
	}
	err := client.Start()
	return client, err
}

var clientFactoryFn = clientFactory
