//go:build ignore
// +build ignore

// This file is modified after tun/netstack/examples/ping_client.go in the
// wireguard-go implementation.

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2022 Ain Ghazal. All Rights Reversed.
 */
package main

import (
	"bytes"
	"log"
	"math/rand"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/ooni/minivpn/vpn"
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

	socket, err := dialer.Dial("ping4", "riseup.net")
	if err != nil {
		log.Panic(err)
	}
	requestPing := icmp.Echo{
		Seq:  rand.Intn(1 << 16),
		Data: []byte("hello filternet"), // get the start ts in here, as sbasso suggested
	}
	icmpBytes, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &requestPing}).Marshal(nil)
	socket.SetReadDeadline(time.Now().Add(time.Second * 10))
	start := time.Now()

	_, err = socket.Write(icmpBytes)
	if err != nil {
		log.Panic(err)
	}

	n, err := socket.Read(icmpBytes[:])
	if err != nil {
		log.Panic(err)
	}
	replyPacket, err := icmp.ParseMessage(1, icmpBytes[:n])
	if err != nil {
		log.Panic(err)
	}
	replyPing, ok := replyPacket.Body.(*icmp.Echo)
	if !ok {
		log.Panicf("invalid reply type: %v", replyPacket)
	}
	if !bytes.Equal(replyPing.Data, requestPing.Data) || replyPing.Seq != requestPing.Seq {
		log.Panicf("invalid ping reply: %v", replyPing)
	}
	log.Printf("Ping latency: %v", time.Since(start))
}
