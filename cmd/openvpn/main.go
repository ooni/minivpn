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
	"github.com/jackpal/gateway"
)

func runCmd(binaryPath string, args ...string) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	err := cmd.Run()
	if nil != err {
		log.WithError(err).Warn("error running /sbin/ip")
	}
}

func runIP(args ...string) {
	runCmd("/sbin/ip", args...)
}

func runRoute(args ...string) {
	runCmd("/sbin/route", args...)
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
	fmt.Printf("Local IP: %s\n", tunnel.LocalAddr())
	fmt.Printf("Gateway:  %s\n", tunnel.RemoteAddr())

	// create a tun interface on the OS
	iface, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		log.WithError(err).Fatal("Unable to allocate TUN interface:")
	}

	// TODO: investigate what's the maximum working MTU, additionally get it from flag.
	MTU := 1400
	iface.SetMTU(MTU)

	localAddr := tunnel.LocalAddr().String()
	remoteAddr := tunnel.RemoteAddr().String()

	// discover local gateway IP, to
	defaultGatewayIP, err := gateway.DiscoverGateway()
	if err != nil {
		log.Warn("could not discover default gateway IP, routes might be broken")
	}
	defaultInterfaceIP, err := gateway.DiscoverInterface()
	if err != nil {
		log.Warn("could not discover default route interface IP, routes might be broken")
	}
	defaultInterface, err := getInterfaceByIP(defaultInterfaceIP.String())
	if err != nil {
		log.Warn("could not get default route interface, routes might be broken")
	}

	if defaultGatewayIP != nil && defaultInterface != nil {
		log.Infof("route add %s gw %v dev %s", options.Remote, defaultGatewayIP, defaultInterface.Name)
		runRoute("add", options.Remote, "gw", defaultGatewayIP.String(), defaultInterface.Name)
	}

	// configure the interface and bring it up
	runIP("addr", "add", localAddr, "dev", iface.Name())
	runIP("link", "set", "dev", iface.Name(), "up")
	runRoute("add", remoteAddr, "gw", localAddr)
	// TODO this has the hardcoded network for TCP
	// To do it properly, we need to parse server options.
	// We could also honor DNS etc.
	// get: route-gateway[0] 10.41.0.1
	// get: ifconfig[1] 255.255.248.0
	runRoute("add", "-net", "10.41.0.0/21", "dev", iface.Name())
	runIP("route", "add", "default", "via", remoteAddr, "dev", iface.Name())

	go func() {
		for {
			packet := make([]byte, 2000)
			n, err := iface.Read(packet)
			if err != nil {
				log.WithError(err).Fatal("error reading from tun")
			}
			tunnel.Write(packet[:n])
			//log.Infof("tun: packet received: % x\n", packet[:n])
		}
	}()
	go func() {
		for {
			packet := make([]byte, 2000)
			n, err := tunnel.Read(packet)
			if err != nil {
				log.WithError(err).Fatal("error reading from tun")
			}
			iface.Write(packet[:n])
			//log.Infof("tun: packet sent: % x\n", packet[:n])
		}
	}()
	select {}
}

func getInterfaceByIP(ipAddr string) (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				if ipNet.IP.String() == ipAddr {
					return &iface, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("interface with IP %s not found", ipAddr)
}