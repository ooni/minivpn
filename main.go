package main

import (
	"fmt"
	"os"

	"github.com/ainghazal/minivpn/vpn"
	"github.com/pborman/getopt/v2"
)

func printUsage() {
	fmt.Println("valid commands: ping, proxy")
	getopt.Usage()
	os.Exit(0)
}

func main() {
	optConfig := getopt.StringLong("config", 'c', "", "Configuration file")
	optServer := getopt.StringLong("server", 's', "", "VPN Server to connect to")
	optTarget := getopt.StringLong("target", 't', "8.8.8.8", "Target for ICMP Ping")
	optCount := getopt.Uint32Long("count", 'n', uint32(3), "Stop after sending these many ECHO_REQUEST packets")

	//optPort := getopt.StringLong("port", 'p', "1194", "UDP Port to connect to (default: 1194)")
	//optCa := getopt.StringLong("ca", 'a', "", "Pemfile with provider's CA")
	//optCert := getopt.StringLong("cert", 'e', "", "Pemfile with Client's certificate")
	//optKey := getopt.StringLong("key", 'k', "", "Pemfile with Client's private key")

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
		raw := vpn.NewRawDialer(opts)
		pinger := NewPinger(raw, *optTarget, *optCount)
		pinger.Run()
	case "proxy":
		ListenAndServeSocks(opts)
	default:
		printUsage()
	}
}
