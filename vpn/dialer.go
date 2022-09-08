package vpn

//
// This file contains dialer types and functions that allow transparent use of
// an OpenVPN connection.
//

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var (
	openDNSPrimary   = "208.67.222.222"
	openDNSSecondary = "208.67.220.220"
)

// DialerContext is anything that features a net.Dialer-like DialContext method.
type DialerContext interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// A TunDialer contains options for obtaining a network connection tunneled
// through an OpenVPN endpoint. It uses a userspace gVisor virtual device over
// the raw OpenVPN tunnel.
//
// You need to be careful and create only one instance of TunDialer for each
// Client, since the underlying virtual device will connect both ends of the
// tunnel.
type TunDialer struct {
	// Dialer will be passed to the underlying Client constructor.
	Dialer          DialerContext
	client          *Client
	ns1             string
	ns2             string
	skipDeviceSetup bool
	device          *device
	tun             *netstack.Net
	mu              sync.Mutex

	// dependency injection to test client start
	clientStartFn func(context.Context) error
}

// NewTunDialer creates a new Dialer with the default nameservers (OpenDNS).
func NewTunDialer(client *Client) *TunDialer {
	td := &TunDialer{
		client: client,
		ns1:    openDNSPrimary,
		ns2:    openDNSSecondary,
	}
	return td
}

// NewTunDialerWithNameservers creates a new TunDialer with the passed nameservers.
// You probably want to pass the nameservers for your own VPN service here.
func NewTunDialerWithNameservers(client *Client, ns1, ns2 string) *TunDialer {
	td := &TunDialer{
		client: client,
		ns1:    ns1,
		ns2:    ns2,
	}
	return td
}

// TODO I might want to create a new constructor that can also accept a custom dialer. Right
// now it's not possible to "create and start" a tundialer only from options
// with an arbitrary dialer. But maybe it's not needed.

// StartNewTunDialerFromOptions creates a new Dialer directly from an Options
// object. It also starts the underlying client.
func StartNewTunDialerFromOptions(opt *Options) (*TunDialer, error) {
	client := NewClientFromOptions(opt)
	err := client.Start(context.Background())
	if err != nil {
		defer client.Close()
		return nil, err
	}
	td := &TunDialer{
		client: client,
		ns1:    openDNSPrimary,
		ns2:    openDNSSecondary,
	}
	return td, nil
}

// Dial connects to the address on the named network, via the OpenVPN endpoint
// in the Client that this TunDialer is initialized with.
//
// The return value implements the net.Conn interface, but it is a socket created
// on a virtual device, using gVisor userspace network stack. This means that the
// kernel only sees UDP packets with an encrypted payload.
//
// The addresses are resolved via the OpenVPN tunnel too, and against the nameservers
// configured in the dialer. This feature uses wireguard's little custom DNS client
// implementation.
//
// Dial calls DialContext with the background context. See documentation of
// DialContext for more details.
//
// Known networks are "tcp", "tcp4" (IPv4-only), "tcp6" (IPv6-only),
// "udp", "udp4" (IPv4-only), "udp6" (IPv6-only), "ping4", "ping6".
func (td *TunDialer) Dial(network, address string) (net.Conn, error) {
	ctx := context.Background()
	tnet, err := td.createNetTUN(ctx)
	if err != nil {
		return nil, err
	}
	return tnet.Dial(network, address)
}

// DialContext connects to the address on the named network using
// the provided context.
//
// The underlying tun is created just once upon successive invocations of
// DialContext.
func (td *TunDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	td.mu.Lock()
	defer td.mu.Unlock()
	if td.tun == nil {
		tnet, err := td.createNetTUN(ctx)
		if err != nil {
			return nil, err
		}
		td.tun = tnet
	}
	return td.tun.DialContext(ctx, network, address)
}

// DialTimeout acts like Dial but takes a timeout.
func (td *TunDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	conn, err := td.Dial(network, address)
	if err != nil {
		return nil, err
	}
	err = conn.SetReadDeadline(time.Now().Add(timeout))
	return conn, err
}

func (td *TunDialer) createNetTUN(ctx context.Context) (*netstack.Net, error) {
	localIP := td.client.LocalAddr().String()

	// create a virtual device in userspace, courtesy of wireguard-go
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.Addr(netip.MustParseAddr(localIP))},
		[]netip.Addr{
			netip.MustParseAddr(td.ns1),
			netip.MustParseAddr(td.ns2)},
		td.client.tunInfo.mtu-100,
	)
	// TODO(https://github.com/ooni/minivpn/issues/26):
	// we cannot use the tun-mtu that the remote advertises, so we subtract
	// a "safety" margin for the time being.

	if err != nil {
		return nil, err
	}

	// connect the virtual device to our openvpn tunnel
	if !td.skipDeviceSetup {
		dev := &device{tun, td.client}
		dev.Up()
		td.device = dev
	}
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
// TODO(https://github.com/ooni/minivpn/issues/27): we probably want a way of
// shutting them down too.
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
