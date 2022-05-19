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

// A Dialer contains options for obtaining a network connection tunneled
// through an OpenVPN endpoint.
type Dialer struct {
	ns1    string
	ns2    string
	vpn    *VPNDialer
	net    *netstack.Net
	DialFn DialFunc
}

// NewDialer creates a new Dialer with the default nameservers (OpenDNS).
func NewDialer(vpn *VPNDialer) Dialer {
	return Dialer{vpn: vpn, ns1: openDNSPrimary, ns2: openDNSSecondary, net: nil}
}

// NewDialerWithNameservers creates a new Dialer with the passed nameservers.
// You probably want to pass the nameservers for your own VPN service here.
func NewDialerWithNameservers(vpn *VPNDialer, ns1, ns2 string) Dialer {
	return Dialer{vpn: vpn, ns1: ns1, ns2: ns2, net: nil}
}

// NewDialerFromOptions creates a new Dialer directly from an Options object.
func NewDialerFromOptions(opt *Options) Dialer {
	vpn := NewVPNDialer(opt)
	return Dialer{vpn: vpn, ns1: openDNSPrimary, ns2: openDNSSecondary, net: nil}
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
	if d.net != nil {
		return d.net.Dial(network, address)
	}
	tnet, err := d.createNetTUN()
	if err != nil {
		return nil, err
	}
	d.net = tnet
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
	if d.net != nil {
		return d.net.DialContext(ctx, network, address)
	}
	tnet, err := d.createNetTUN()
	if err != nil {
		return nil, err
	}
	d.net = tnet
	return tnet.DialContext(ctx, network, address)
}

func (d Dialer) Stop() {
	// For testing, ndt7 etc is possible that we're using a raw dialer with no
	// tunnel, e.g., just using the net.Dial as the dial function. in that case
	// we don't have no client to stop.
	if d.vpn != nil && d.vpn.vpnClient == nil {
		d.vpn.vpnClient.Stop()
	}
}

func (d Dialer) createNetTUN() (*netstack.Net, error) {
	if d.DialFn != nil {
		d.vpn.dialFn = d.DialFn
	}
	vpnConn, err := d.vpn.Dial()
	if err != nil {
		return nil, err
	}
	localIP := vpnConn.LocalAddr().String()

	// create a virtual device in userspace, courtesy of wireguard-go
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(localIP)},
		[]netip.Addr{
			netip.MustParseAddr(d.ns1),
			netip.MustParseAddr(d.ns2)},
		d.vpn.vpnClient.tunnel.mtu-100,
	)
	// BUG(ainghazal): we cannot use the tun-mtu that the remote advertises, so we substract a "safety" margin for now.
	if err != nil {
		return nil, err
	}

	// connect the virtual device to our openvpn tunnel
	dev := &device{tun, vpnConn}
	dev.Up()

	return tnet, nil
}

// device contains the two halves of the tunnel that we are connecting in our
// toy implementation: the virtual tun device that is handled by netstack, and
// the raw PacketConn that writes and reads to sockets provided by the kernel.
type device struct {
	tun     tun.Device
	vpnConn net.Conn
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
			d.vpnConn.Write(b[0:n])
		}
	}()
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := d.vpnConn.Read(b)
			if err != nil {
				logger.Errorf("raw read error: %v", err)
				break
			}
			d.tun.Write(b[0:n], 0) // zero offset
		}
	}()
}

type VPNDialer struct {
	Options   *Options
	vpnClient *Client
	dialFn    DialFunc
}

func NewVPNDialer(opts *Options) *VPNDialer {
	return &VPNDialer{Options: opts}
}

// Dial returns a net.Conn that writes to and reads (raw packets) from the VPN
// tunnel.
func (d *VPNDialer) Dial() (net.Conn, error) {
	if d.vpnClient == nil {
		c := NewClientFromSettings(d.Options)
		if d.dialFn != nil {
			c.DialFn = d.dialFn
		}
		d.vpnClient = c
		err := d.vpnClient.Start()
		if err != nil {
			return nil, err
		}
	}
	return net.Conn(d.vpnClient), nil
}
