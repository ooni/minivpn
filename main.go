package main

import (
	"fmt"
	"os"

	"github.com/ainghazal/minivpn/vpn"
	"github.com/pborman/getopt"
)

func main() {
	optConfig := getopt.StringLong("config", 'c', "", "Configuration file")
	optServer := getopt.StringLong("server", 's', "", "VPN Server to connect to")
	optPort := getopt.StringLong("port", 'p', "1194", "UDP Port to connect to (default: 1194)")
	optTarget := getopt.StringLong("target", 't', "8.8.8.8", "Target for ICMP Ping")
	optCount := getopt.Uint32Long("count", 'n', uint32(3), "Stop after sending these many ECHO_REQUEST packets")

	optCa := getopt.StringLong("ca", 'a', "", "Pemfile with provider's CA")
	optCert := getopt.StringLong("cert", 'e', "", "Pemfile with Client's certificate")
	optKey := getopt.StringLong("key", 'k', "", "Pemfile with Client's private key")

	helpFlag := getopt.Bool('h', "Display help")

	getopt.Parse()
	fmt.Println("config file:", *optConfig)

	if *helpFlag || (*optServer == "" && *optConfig == "") {
		getopt.Usage()
		os.Exit(0)
	}

	var c *vpn.Client

	if *optConfig != "" {
		opts, err := vpn.ParseConfigFile(*optConfig)
		if err != nil {
			fmt.Println("fatal: " + err.Error())
			os.Exit(1)
		}
		c = vpn.NewClientFromSettings(opts)
	} else {
		o := &vpn.Options{
			Remote: *optServer,
			Port:   *optPort,
			Proto:  "udp",
			Ca:     *optCa,
			Cert:   *optCert,
			Key:    *optKey,
		}
		c = vpn.NewClientFromSettings(o)
	}
	done := make(chan bool)
	c.DataHandler = NewPinger(c, *optTarget, *optCount, done)
	c.WaitUntil(done)
	c.Run()
}
