// This file is modified after tun/netstack/examples/http_client.go in the
// wireguard-go implementation.

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2022 Ain Ghazal. All Rights Reversed.
 */
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"openVPN/vpn"
)

func main() {
	opts, err := vpn.NewOptionsFromFilePath("openvpn/kolosya.conf")
	if err != nil {
		panic(err)
	}
	c := vpn.NewClientFromOptions(opts)
	dialer := vpn.NewTunDialer(c)
	if err != nil {
		log.Panic(err)
	}

	ctx := context.Background()
	err = c.Start(ctx)
	if err != nil {
		log.Panic(err)
	}

	client := http.Client{
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
		},
	}

	resp, err := client.Get("http://lib.ru")
	if err != nil {
		log.Panic(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Panic(err)
	}
	fmt.Println(string(body))
}
