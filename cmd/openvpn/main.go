package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/networkio"
	"github.com/ooni/minivpn/internal/tun"

	"github.com/Doridian/water"
)

func runIP(args ...string) {
	cmd := exec.Command("/sbin/ip", args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	err := cmd.Run()
	if nil != err {
		log.WithError(err).Fatal("error running /sbin/ip")
	}
}

func runRoute(args ...string) {
	cmd := exec.Command("/sbin/route", args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	err := cmd.Run()
	if nil != err {
		log.WithError(err).Fatal("error running /sbin/route")
	}
}

func main() {
	log.SetLevel(log.DebugLevel)

	// parse the configuration file
	options, err := model.ReadConfigFile(os.Args[1])
	if err != nil {
		log.WithError(err).Fatal("NewOptionsFromFilePath")
	}
	log.Infof("parsed options: %s", options.ServerOptionsString())

	// TODO(ainghazal): move the initialization step to an early phase and keep a ref in the muxer
	if !options.HasAuthInfo() {
		log.Fatal("options are missing auth info")
	}
	// connect to the server
	dialer := networkio.NewDialer(log.Log, &net.Dialer{})
	ctx := context.Background()
	endpoint := net.JoinHostPort(options.Remote, options.Port)
	conn, err := dialer.DialContext(ctx, options.Proto.String(), endpoint)
	if err != nil {
		log.WithError(err).Fatal("dialer.DialContext")
	}

	// create a vpn tun Device
	tunnel := tun.StartTUN(conn, options)
	fmt.Println(tunnel.LocalAddr())
	fmt.Println(tunnel.RemoteAddr())

	// create a tun interface on the OS
	iface, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		log.WithError(err).Fatal("Unable to allocate TUN interface:")
	}

	MTU := 1400
	iface.SetMTU(MTU)

	localAddr := tunnel.LocalAddr().String()
	remoteAddr := tunnel.RemoteAddr().String()

	// TODO: missing
	// sudo route add 163.172.211.109 gw 192.168.18.1 enp38s0

	// configure the interface and bring it up
	runIP("addr", "add", localAddr, "dev", iface.Name())
	runIP("link", "set", "dev", iface.Name(), "up")
	runRoute("add", remoteAddr, "gw", localAddr)
	// TODO this has hardcoded network for UDP
	runRoute("add", "-net", "10.42.0.0/21", "dev", iface.Name())
	runIP("route", "add", "default", "via", remoteAddr, "dev", iface.Name())
	fmt.Println("iface", iface)

	go func() {
		packet := make([]byte, 2000)
		for {
			n, err := iface.Read(packet)
			if err != nil {
				log.WithError(err).Fatal("error reading from tun")
			}
			tunnel.Write(packet[:n])
			log.Infof("tun: packet received: % x\n", packet[:n])
		}
	}()
	go func() {
		packet := make([]byte, 2000)
		for {
			n, err := tunnel.Read(packet)
			if err != nil {
				log.WithError(err).Fatal("error reading from tun")
			}
			iface.Write(packet[:n])
			log.Infof("tun: packet sent: % x\n", packet[:n])
		}
	}()
	select {}
}

// /sbin/route add 10.42.0.1 gw 10.42.0.9
// /sbin/route add -net 10.42.0.0/24 dev tun0
// /sbin/ip route add default via 10.42.0.1 dev tun0
