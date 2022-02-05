package main

import (
	"github.com/kalikaneko/minivpn/vpn"
)

func main() {
	c := &vpn.Client{
		// FIXME remove hardcoded ip
		// get it from conf file
		Host:  "1.1.1.1",
		Port:  "1194",
		Proto: "udp",
	}
	c.DataHandler = NewPinger(c, "8.8.8.8")
	c.Run()
}
