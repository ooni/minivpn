package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/Doridian/water"
	"github.com/apex/log"
	"github.com/jackpal/gateway"

	"github.com/ooni/minivpn/extras/ping"
	"github.com/ooni/minivpn/internal/runtimex"
	"github.com/ooni/minivpn/pkg/config"
	"github.com/ooni/minivpn/pkg/tracex"
	"github.com/ooni/minivpn/pkg/tunnel"
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

type cmdConfig struct {
	configPath string
	doPing     bool
	doTrace    bool
	skipRoute  bool
	timeout    int
}

func main() {
	log.SetLevel(log.DebugLevel)

	cfg := &cmdConfig{}
	flag.StringVar(&cfg.configPath, "config", "", "config file to load")
	flag.BoolVar(&cfg.doPing, "ping", false, "if true, do ping and exit (for testing)")
	flag.BoolVar(&cfg.doTrace, "trace", false, "if true, do a trace of the handshake and exit (for testing)")
	flag.BoolVar(&cfg.skipRoute, "skip-route", false, "if true, exit without setting routes (for testing)")
	flag.IntVar(&cfg.timeout, "timeout", 60, "timeout in seconds (default=60)")
	flag.Parse()

	if cfg.configPath == "" {
		fmt.Println("[error] need config path")
		os.Exit(1)
	}

	log.SetHandler(NewHandler(os.Stderr))
	log.SetLevel(log.DebugLevel)

	opts := []config.Option{
		config.WithConfigFile(cfg.configPath),
		config.WithLogger(log.Log),
	}

	start := time.Now()

	var tracer *tracex.Tracer
	if cfg.doTrace {
		tracer = tracex.NewTracer(start)
		opts = append(opts, config.WithHandshakeTracer(tracer))
		defer func() {
			trace := tracer.Trace()
			jsonData, err := json.MarshalIndent(trace, "", "  ")
			runtimex.PanicOnError(err, "cannot serialize trace")
			fileName := fmt.Sprintf("handshake-trace-%s.json", time.Now().Format("2006-01-02-15:05:00"))
			os.WriteFile(fileName, jsonData, 0644)
			fmt.Println("trace written to", fileName)
		}()
	}

	// The TLS will expire in 60 seconds by default, but we can pass
	// a shorter timeout.
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.timeout)*time.Second)
	defer cancel()

	// create config from the passed options
	vpncfg := config.NewConfig(opts...)

	// create a vpn tun Device
	tun, err := tunnel.Start(ctx, &net.Dialer{}, vpncfg)
	if err != nil {
		log.WithError(err).Error("init error")
		return
	}
	log.Infof("Local IP: %s\n", tun.LocalAddr())
	log.Infof("Gateway:  %s\n", tun.RemoteAddr())

	fmt.Println("initialization-sequence-completed")
	fmt.Printf("elapsed: %v\n", time.Since(start))

	if cfg.doTrace {
		return
	}

	if cfg.doPing {
		pinger := ping.New("8.8.8.8", tun)
		count := 5
		pinger.Count = count

		err = pinger.Run(context.Background())
		if err != nil {
			pinger.PrintStats()
			log.WithError(err).Fatal("ping error")
		}
		pinger.PrintStats()
		os.Exit(0)
	}

	if cfg.skipRoute {
		os.Exit(0)
	}

	// create a tun interface on the OS
	iface, err := water.New(water.Config{DeviceType: water.TUN})
	runtimex.PanicOnError(err, "unable to open tun interface")

	// TODO: investigate what's the maximum working MTU, additionally get it from flag.
	MTU := 1420
	iface.SetMTU(MTU)

	localAddr := tun.LocalAddr().String()
	remoteAddr := tun.RemoteAddr().String()
	netMask := tun.NetMask()

	// discover local gateway IP, we need it to add a route to our remote via our network gw
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
		log.Infof("route add %s gw %v dev %s", vpncfg.Remote().IPAddr, defaultGatewayIP, defaultInterface.Name)
		runRoute("add", vpncfg.Remote().IPAddr, "gw", defaultGatewayIP.String(), defaultInterface.Name)
	}

	// we want the network CIDR for setting up the routes
	network := &net.IPNet{
		IP:   net.ParseIP(localAddr).Mask(netMask),
		Mask: netMask,
	}

	// configure the interface and bring it up
	runIP("addr", "add", localAddr, "dev", iface.Name())
	runIP("link", "set", "dev", iface.Name(), "up")
	runRoute("add", remoteAddr, "gw", localAddr)
	runRoute("add", "-net", network.String(), "dev", iface.Name())
	runIP("route", "add", "default", "via", remoteAddr, "dev", iface.Name())

	go func() {
		for {
			packet := make([]byte, 2000)
			n, err := iface.Read(packet)
			if err != nil {
				log.WithError(err).Fatal("error reading from tun")
			}
			tun.Write(packet[:n])
		}
	}()
	go func() {
		for {
			packet := make([]byte, 2000)
			n, err := tun.Read(packet)
			if err != nil {
				log.WithError(err).Fatal("error reading from tun")
			}
			iface.Write(packet[:n])
		}
	}()
	select {}
}
