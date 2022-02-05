package main

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

func newPinger(c *vpn.Client) pinger {
	// TODO get it from opts, via args
	host := "8.8.8.8"
	return pinger{c: c, host: host}
}

type pinger struct {
	c    *vpn.Client
	dc   chan []byte
	host string
}

func (p pinger) InitConsumer() {
	p.dc = p.c.GetDataChannel()
	p.SendPayload()
	go p.ConsumeData()
}

func (p pinger) ConsumeData() {
	for {
		select {
		case data := <-p.dc:
			p.handleIncoming(data)
		}
	}
}

func (p pinger) SendPayload() {
	src := p.c.GetTunnelIP()
	log.Println("Sending PING from", src)

	srcIP := net.ParseIP(src)
	dstIP := net.ParseIP(p.host)

	buf := newIcmpData(&srcIP, &dstIP, 8, 64)
	log.Println("len:", len(buf))
	p.c.SendData(buf)
}

func (p pinger) handleIncoming(d []byte) {
	log.Println(">>> RECEIVED PING DATA", d)
	// XXX now do something with this :^)
}

func newIcmpData(src, dest *net.IP, typeCode, ttl int) (data []byte) {
	ip := &layers.IPv4{}
	ip.Version = 4
	ip.Protocol = layers.IPProtocolICMPv4
	ip.SrcIP = *src
	ip.DstIP = *dest

	log.Println(ip.SrcIP)
	log.Println(ip.DstIP)

	ip.Length = 20
	ip.TTL = uint8(ttl)

	icmp := &layers.ICMPv4{}
	icmp.TypeCode = layers.ICMPv4TypeCode(uint16(typeCode) << 8)
	icmp.Id = uint16(os.Getpid() & 0xffff)
	icmp.Seq = 0
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
