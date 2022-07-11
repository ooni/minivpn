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
	opts, err := vpn.ParseConfigFile(cfg)
	if err != nil {
		os.Exit(1)
	}
	rawDialer := vpn.NewRawDialer(opts)
	conn, err := rawDialer.Dial()
	if err != nil {
		panic(err)
	}
	pinger := ping.New(target, conn)
	pinger.Count = 3
	pinger.Timeout = 5 * time.Second
	pinger.Run(context.Background())
}
