//go:build ignore
// +build ignore

// This file is modified after tun/netstack/examples/http_client.go in the
// wireguard-go implementation.

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2022 Ain Ghazal. All Rights Reversed.
 */
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/ooni/minivpn/vpn"

	"runtime"
	"runtime/pprof"
)

var cpuprofile = flag.String("cpuprof", "", "write cpu profile to `file`")
var url = flag.String("url", "", "url to fetch")

func main() {
	flag.Parse()
	if *cpuprofile != "" {
		runtime.SetCPUProfileRate(60)
		log.Println("creating cpu profile at:", *cpuprofile)
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close() // error handling omitted for example
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}
	provider := os.Getenv("PROVIDER")
	if provider == "" {
		log.Fatal("Export the PROVIDER variable")
	}
	opts, err := vpn.ParseConfigFile("data/" + provider + "/config")
	if err != nil {
		panic(err)
	}
	dialer := vpn.NewDialerFromOptions(opts)
	if err != nil {
		log.Panic(err)
	}

	client := http.Client{
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
		},
	}
	// BUG(ainghazal): https stalls unless I tweak the tun-mtu that the
	// remote announces. I might want to look at the mtu discovery that
	// openvpn does.
	//if len(os.Args) != 2 {
	//	log.Println("Usage: get <https://foobar>")
	//	os.Exit(1)
	//}

	resp, err := client.Get(*url)
	if err != nil {
		log.Panic(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Panic(err)
	}
	fmt.Println(string(body))
}
