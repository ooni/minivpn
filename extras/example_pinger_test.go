package extras

import (
	"context"
	"os"
	"time"

	"github.com/ooni/minivpn/extras/ping"
	"github.com/ooni/minivpn/vpn"
)

var (
	cfg    = "data/riseup/config"
	target = "8.8.8.8"
	count  = 3
)

func ExamplePinger() {
	opts, err := vpn.NewOptionsFromFilePath(cfg)
	if err != nil {
		os.Exit(1)
	}
	tunnel := vpn.NewClientFromOptions(opts)
	tunnel.Start(context.Background())
	pinger := ping.New(target, tunnel)
	pinger.Count = 3
	pinger.Timeout = 5 * time.Second
	pinger.Run(context.Background())
}
