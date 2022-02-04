package main

import (
	"github.com/kalikaneko/minivpn/vpn"
)

func main() {
	c := &vpn.Client{
		Host:  "1.1.1.1",
		Port:  "1194",
		Proto: "udp",
	}
	c.DataHandler = newPinger(c)
	c.Run()
}
