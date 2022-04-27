package main

import (
	"fmt"
	"os"

	"github.com/pborman/getopt/v2"

	"github.com/ainghazal/minivpn/extras"
	"github.com/ainghazal/minivpn/vpn"
)

func printUsage() {
	fmt.Println("valid commands: ping, proxy")
	getopt.Usage()
	os.Exit(0)
}

// RunPinger takes an Option object, gets a Dialer, and runs a Pinger against
// the passed target, for count packets.
func RunPinger(o *vpn.Options, target string, count uint32) error {
	raw := vpn.NewRawDialer(o)
	pinger := extras.NewPinger(raw, target, int(count))
	err := pinger.Run()
	if err != nil {
		// TODO identify different errors
		os.Exit(42)
	}
	pinger.Stop()
	return nil
}

func main() {
	optConfig := getopt.StringLong("config", 'c', "", "Configuration file")
	optServer := getopt.StringLong("server", 's', "", "VPN Server to connect to")
	optTarget := getopt.StringLong("target", 't', "8.8.8.8", "Target for ICMP Ping")
	optCount := getopt.Uint32Long("count", 'n', uint32(3), "Stop after sending these many ECHO_REQUEST packets")

	helpFlag := getopt.Bool('h', "Display help")

	getopt.Parse()
	args := getopt.Args()

	if len(args) != 1 {
		printUsage()

	}
	fmt.Println("config file:", *optConfig)

	if *helpFlag || (*optServer == "" && *optConfig == "") {
		printUsage()
	}

	var opts *vpn.Options

	opts, err := vpn.ParseConfigFile(*optConfig)
	if err != nil {
		fmt.Println("fatal: " + err.Error())
		os.Exit(1)
	}
	switch args[0] {
	case "ping":
		RunPinger(opts, *optTarget, *optCount)
	case "proxy":
		ListenAndServeSocks(opts)
	default:
		printUsage()
	}
}
