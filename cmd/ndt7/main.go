package main

import (
	"os"

	"github.com/ainghazal/minivpn/extras"
	"github.com/ainghazal/minivpn/vpn"
)

func main() {
	// TODO fail if no server provided
	ndt7Server := os.Getenv("SERVER")

	opts, err := vpn.ParseConfigFile("data/calyx/config")
	if err != nil {
		panic(err)
	}
	dialer := vpn.NewDialerFromOptions(opts)
	extras.RunMeasurement(dialer, ndt7Server)
}
