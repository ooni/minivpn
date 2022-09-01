package main

import (
	"fmt"
	"net"
	"os"

	socks5 "github.com/armon/go-socks5"
	"github.com/ooni/minivpn/vpn"
)

const (
	socksPort = "8080"
	socksIP   = "127.0.0.1"
)

// ListenAndServeSocks configures a vpn dialer, and configures and runs a
// socks5 server to use dialer.DialContext. The vpn dialer will initialize the tunnel
// upon receiving the first proxied request, and will reuse the same session
// for all further requests.
func ListenAndServeSocks(opts *vpn.Options) {
	port := os.Getenv("LPORT")
	if port == "" {
		port = socksPort
	}
	ip := os.Getenv("LHOST")
	if ip == "" {
		ip = socksIP
	}
	dialer, err := vpn.StartNewTunDialerFromOptions(opts, &net.Dialer{})
	if err != nil {
		panic(err)
	}
	conf := &socks5.Config{
		Dial: dialer.DialContext,
	}
	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}

	addr := net.JoinHostPort(ip, port)
	fmt.Printf("[+] Started socks5 proxy at %s\n", addr)
	if err := server.ListenAndServe("tcp", addr); err != nil {
		panic(err)
	}
}
