package main

import (
	"bytes"
	"log"
	"math/rand"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"golang.zx2c4.com/go118/netip"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/ainghazal/minivpn/vpn"
)

// XXX just for testing, get it from cli params
func vpnRawDialer() *vpn.RawDialer {
	opts, err := vpn.ParseConfigFile("data/calyx/config")
	if err != nil {
		panic(err)
	}
	return vpn.NewRawDialer(opts)
}

// -------------------- move to dialer ------------------------------------

type device struct {
	tun tun.Device
	raw net.PacketConn
}

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

type Dialer struct {
	NameServer string
	raw        *vpn.RawDialer
}

func NewDialer(raw *vpn.RawDialer) Dialer {
	ns := "8.8.8.8" // it'd be nice to get this config externally.
	return Dialer{raw: raw, NameServer: ns}
}

func (d Dialer) Dial(network, address string) (net.Conn, error) {
	raw, err := d.raw.Dial()
	if err != nil {
		return nil, err
	}
	localIP := raw.LocalAddr().String()
	// create a virtual device in userspace, courtesy of wireguard-go
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(localIP)},
		[]netip.Addr{netip.MustParseAddr(d.NameServer)},
		d.raw.MTU)
	if err != nil {
		return nil, err
	}
	// connect the virtual device to our openvpn tunnel
	dev := &device{tun, raw}
	dev.Up()
	return tnet.Dial(network, address)
}

// perhaps useful to implement too?
// just set the socket deadline at now + timeout, I think...
// func DialTimeout(network, address string, timeout time.Duration) (Conn, error)
// socket.SetReadDeadline(time.Now().Add(time.Second * 10))

// ----------------------------------------------------------------------------

func main() {
	raw := vpnRawDialer()
	dialer := NewDialer(raw)
	socket, err := dialer.Dial("ping4", "8.8.8.8")
	if err != nil {
		log.Panic(err)
	}
	requestPing := icmp.Echo{
		Seq:  rand.Intn(1 << 16),
		Data: []byte("hello filternet"), // get the start ts in here, as sbasso suggested
	}
	icmpBytes, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &requestPing}).Marshal(nil)
	socket.SetReadDeadline(time.Now().Add(time.Second * 10))
	start := time.Now()

	_, err = socket.Write(icmpBytes)
	if err != nil {
		log.Panic(err)
	}

	n, err := socket.Read(icmpBytes[:])
	if err != nil {
		log.Panic(err)
	}
	replyPacket, err := icmp.ParseMessage(1, icmpBytes[:n])
	if err != nil {
		log.Panic(err)
	}
	replyPing, ok := replyPacket.Body.(*icmp.Echo)
	if !ok {
		log.Panicf("invalid reply type: %v", replyPacket)
	}
	if !bytes.Equal(replyPing.Data, requestPing.Data) || replyPing.Seq != requestPing.Seq {
		log.Panicf("invalid ping reply: %v", replyPing)
	}
	log.Printf("Ping latency: %v", time.Since(start))
}
