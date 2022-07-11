package main

import (
	"context"
	"log"

	"github.com/ooni/minivpn/extras/ping"
	"github.com/ooni/minivpn/vpn"
)

func main() {
	opts, err := vpn.ParseConfigFile("data/riseup/config")
	if err != nil {
		panic(err)
	}
	rawDialer := vpn.NewRawDialer(opts)
	conn, err := rawDialer.DialContext(context.Background())
	if err != nil {
		panic(err)
	}
	pinger := ping.New("8.8.8.8", conn)
	pinger.Count = 3
	err = pinger.Run(context.Background())
	if err != nil {
		log.Fatal(err)
	}
}
