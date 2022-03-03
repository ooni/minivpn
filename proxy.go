package main

import (
	socks5 "github.com/armon/go-socks5"

	"github.com/ainghazal/minivpn/vpn"
)

func ListenAndServeSocks(opts *vpn.Options) {
	dialer := vpn.NewDialerFromOptions(opts)

	// Create a SOCKS5 server
	conf := &socks5.Config{
		Dial: dialer.DialContext,
	}
	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}

	// Create SOCKS5 proxy on localhost port 8000
	if err := server.ListenAndServe("tcp", "127.0.0.1:8000"); err != nil {
		panic(err)
	}
}
