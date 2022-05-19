package main

import (
	"github.com/ainghazal/minivpn/extras"
	"github.com/ainghazal/minivpn/vpn"
)

func main() {
	opts, err := vpn.ParseConfigFile("data/calyx/config")
	if err != nil {
		panic(err)
	}
	vpn := vpn.NewVPNDialer(opts)
	p := extras.NewPinger(vpn, "8.8.8.8", 3)
	p.Run()
	p.Stop()
}
