package main

import (
	"github.com/ainghazal/minivpn/vpn"
)

func main() {
	c := &vpn.Client{
		// FIXME remove hardcoded ip
		// get it from conf file
		Host:  "1.1.1.1",
		Port:  "1194",
		Proto: "udp",
	}
	done := make(chan bool)
	c.DataHandler = NewPinger(c, "8.8.8.8", done)
	c.WaitUntil(done)
	c.Run()
}
