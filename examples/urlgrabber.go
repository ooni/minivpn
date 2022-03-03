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
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/ainghazal/minivpn/vpn"
)

func main() {
	opts, err := vpn.ParseConfigFile("data/calyx/config")
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
	if len(os.Args) != 2 {
		log.Println("Usage: get <https://foobar>")
		os.Exit(1)
	}
	uri := os.Args[1]
	resp, err := client.Get(uri)
	if err != nil {
		log.Panic(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Panic(err)
	}
	fmt.Println(string(body))
}
