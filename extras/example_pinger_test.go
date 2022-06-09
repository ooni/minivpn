package extras

import (
	"os"

	"github.com/ooni/minivpn/vpn"
)

var (
	cfg    = "data/calyx/config"
	target = "8.8.8.8"
	count  = 3
)

func ExamplePinger() {
	opts, err := vpn.ParseConfigFile(cfg)
	if err != nil {
		os.Exit(1)
	}
	rawDialer := vpn.NewRawDialer(opts)
	pinger := NewPinger(rawDialer, target, count)
	pinger.Run()
}
