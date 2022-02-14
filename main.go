package main

import (
	"github.com/ainghazal/minivpn/vpn"
	"os"

	"github.com/pborman/getopt"
)

func main() {
	optServer := getopt.StringLong("server", 's', "", "VPN Server to connect to")
	optPort := getopt.StringLong("port", 'p', "1194", "UDP Port to connect to (default: 1194)")
	optTarget := getopt.StringLong("target", 't', "8.8.8.8", "Target for ICMP Ping")
	optCount := getopt.Uint32Long("count", 'c', uint32(3), "Stop after sending these many ECHO_REQUEST packets")
	getopt.Parse()

	if *optServer == "" {
		getopt.Usage()
		os.Exit(0)
	}

	c := &vpn.Client{
		// FIXME dns resolution
		// FIXME ip validation
		Host:  *optServer,
		Port:  *optPort,
		Proto: "udp",
	}
	done := make(chan bool)
	c.DataHandler = NewPinger(c, *optTarget, *optCount, done)
	c.WaitUntil(done)
	c.Run()
}
