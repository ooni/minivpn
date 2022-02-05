package main

// Portions of this file are modified after github.com/go-ping
// Copyright (c) 2016 Cameron Sparr and contributors.
// Copyright (c) 2022 Ain Ghazal

import (
	"encoding/binary"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/kalikaneko/minivpn/vpn"
)

func NewPinger(c *vpn.Client, host string) Pinger {
	// TODO validate host ip / domain
	return Pinger{c: c, host: host}
}

type Pinger struct {
	c    *vpn.Client
	dc   chan []byte
	host string

	Interval    time.Duration
	Count       int
	PacketsSent int
	PacketsRecv int
}

type packet struct {
	bytes  []byte
	nbytes int
	ttl    int
}

func (p Pinger) Init() {
	p.dc = p.c.GetDataChannel()
	p.SendPayloads()
	go p.ConsumeData()
}

func (p Pinger) ConsumeData() {
	for {
		select {
		case data := <-p.dc:
			p.handleIncoming(data)
		}
	}
}

func (p Pinger) SendPayloads() {
	src := p.c.GetTunnelIP()
	srcIP := net.ParseIP(src)
	dstIP := net.ParseIP(p.host)

	p.craftAndSendICMP(&srcIP, &dstIP, 64, 0)
}

func (p Pinger) craftAndSendICMP(src, dst *net.IP, ttl, seq int) {
	buf := newIcmpData(src, dst, 8, ttl, seq)
	p.c.SendData(buf)
}

func (p Pinger) handleIncoming(d []byte) {
	log.Println(">>> Got ping reply", d)
	var ip layers.IPv4
	var udp layers.UDP
	var icmp layers.ICMPv4
	var payload gopacket.Payload
	decoded := []gopacket.LayerType{}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip, &icmp, &udp, &payload)
	err := parser.DecodeLayers(d, &decoded)
	if err != nil {
		log.Println("error decoding:", err)
	}
	log.Println(decoded)
}

func newIcmpData(src, dest *net.IP, typeCode, ttl, seq int) (data []byte) {
	ip := &layers.IPv4{}
	ip.Version = 4
	ip.Protocol = layers.IPProtocolICMPv4
	ip.SrcIP = *src
	ip.DstIP = *dest

	ip.Length = 20
	ip.TTL = uint8(ttl)

	icmp := &layers.ICMPv4{}
	icmp.TypeCode = layers.ICMPv4TypeCode(uint16(typeCode) << 8)
	icmp.Id = uint16(os.Getpid() & 0xffff)
	icmp.Seq = uint16(seq)
	icmp.Checksum = 0

	opts := gopacket.SerializeOptions{}
	opts.ComputeChecksums = true
	opts.FixLengths = true

	now := time.Now().UnixNano()
	var payload = make([]byte, 8)
	binary.LittleEndian.PutUint64(payload, uint64(now))

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, opts, ip, icmp, gopacket.Payload(payload))

	return buf.Bytes()
}
