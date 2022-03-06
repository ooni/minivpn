package main

import (
	"os"

	"github.com/ainghazal/minivpn/vpn"
)

var (
	cfg    = "data/calyx/config"
	target = "8.8.8.8"
	count  = 3
)

func ExampleRunPinger() {
	opts, err := vpn.ParseConfigFile(cfg)
	if err != nil {
		os.Exit(1)
	}
	raw := vpn.NewRawDialer(opts)
	pinger := NewPinger(raw, target, uint32(count))
	pinger.Run()
}
