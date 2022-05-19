package extras

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
	vpnDialer := vpn.NewVPNDialer(opts)
	pinger := NewPinger(vpnDialer, target, count)
	pinger.Run()
}
