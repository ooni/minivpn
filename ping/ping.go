/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"bytes"
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"

	"encoding/hex"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"golang.zx2c4.com/go118/netip"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/ainghazal/minivpn/vpn"
)

type Device struct {
	tun tun.Device
	raw net.PacketConn
}

func (d *Device) Up() {
	log.Println("Initializing VPN device on virtual interface...")
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := d.tun.Read(b, 0)
			if err != nil {
				log.Println("tun read error:", err)
			} else {
				log.Println("tun->raw")
				d.raw.WriteTo(b[0:n], nil)
			}
		}
	}()
	go func() {
		b := make([]byte, 4096)
		for {
			n, _, err := d.raw.ReadFrom(b)
			if err != nil {
				log.Println("raw read error:", err)
			} else {
				log.Println("raw->tun")
			}
			fmt.Println(hex.Dump(b[0:n]))
			d.tun.Write(b[0:n], 0)
		}
	}()
}

func vpnConn() net.PacketConn {
	opts, err := vpn.ParseConfigFile("data/calyx/config")
	if err != nil {
		panic(err)
	}
	dialer := vpn.NewDialer(opts)
	raw, err := dialer.Dial(nil, "", "")
	if err != nil {
		panic(err)
	}
	return raw
}

func main() {
	raw := vpnConn()
	localIP := raw.LocalAddr().String()
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(localIP)},
		[]netip.Addr{netip.MustParseAddr("8.8.8.8")},
		1500)
	if err != nil {
		log.Panic(err)
	}

	dev := &Device{tun, raw}
	dev.Up()

	socket, err := tnet.Dial("ping4", "8.8.8.8")
	if err != nil {
		log.Panic(err)
	}
	requestPing := icmp.Echo{
		Seq:  rand.Intn(1 << 16),
		Data: []byte("hello filternet"),
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
