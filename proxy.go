package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"

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
	dialer, err := vpn.StartNewTunDialerFromOptions(opts)
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
	fmt.Printf("[+] Starting socks5 proxy at %s\n", addr)
	if err := server.ListenAndServe("tcp", addr); err != nil {
		if isErrorAddressAlreadyInUse(err) {
			fmt.Printf("[!] Address %s already in use\n", addr)
			for i := 1; i < 1e4; i++ {
				addr := net.JoinHostPort(ip, fmt.Sprintf("%d", i+1024))
				fmt.Println("[+] Trying to listen on", addr)
				if err := server.ListenAndServe("tcp", addr); err != nil {
					continue
				}
			}
		} else {
			panic(err)
		}
	}
}

func isErrorAddressAlreadyInUse(err error) bool {
	var eOsSyscall *os.SyscallError
	if !errors.As(err, &eOsSyscall) {
		return false
	}
	var errErrno syscall.Errno // doesn't need a "*" (ptr) because it's already a ptr (uintptr)
	if !errors.As(eOsSyscall, &errErrno) {
		return false
	}
	if errErrno == syscall.EADDRINUSE {
		return true
	}
	const WSAEADDRINUSE = 10048
	if runtime.GOOS == "windows" && errErrno == WSAEADDRINUSE {
		return true
	}
	return false
}
