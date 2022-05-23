package main

import (
	"log"

	"github.com/ainghazal/minivpn/extras"
	"github.com/ainghazal/minivpn/vpn"
)

func main() {
	opts, err := vpn.ParseConfigFile("data/calyx/config")
	if err != nil {
		panic(err)
	}
	raw := vpn.NewRawDialer(opts)
	p := extras.NewPinger(raw, "8.8.8.8", 3)
	err = p.Run()
	if err != nil {
		log.Fatal(err)
	}
}
