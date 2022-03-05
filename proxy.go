package main

import (
	socks5 "github.com/armon/go-socks5"

	"github.com/ainghazal/minivpn/vpn"
)

// ListenAndServeSocks configures a vpn dialer, and configures and runs a
// socks5 server to use dialer.DialContext. The vpn dialer will initialize the tunnel
// upon receiving the first proxied request, and will reuse the same session
// for all further requests.
func ListenAndServeSocks(opts *vpn.Options) {
	dialer := vpn.NewDialerFromOptions(opts)

	conf := &socks5.Config{
		Dial: dialer.DialContext,
	}

	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}

	if err := server.ListenAndServe("tcp", "127.0.0.1:8000"); err != nil {
		panic(err)
	}
}
