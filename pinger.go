package main

// Copyright (c) 2022 Ain Ghazal

import (
	"github.com/ainghazal/minivpn/extras"
	"github.com/ainghazal/minivpn/vpn"
)

// RunPinger takes an Option object, gets a Dialer, and runs a Pinger against
// the passed target, for count packets.
func RunPinger(o *vpn.Options, target string, count uint32) {
	raw := vpn.NewRawDialer(o)
	pinger := extras.NewPinger(raw, target, int(count))
	pinger.Run()
}

/*
----- this raw implementation is obsoleted now that we're using netstack ----

func (p *Pinger) sendPayload(s int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	src := p.conn.LocalAddr().String()
	srcIP := net.ParseIP(src)
	dstIP := net.ParseIP(p.host)
	p.ts[s] = time.Now().UnixNano()
	go p.craftAndSendICMP(&srcIP, &dstIP, p.ttl, s)
	p.packetsSent++
}

func (p *Pinger) craftAndSendICMP(src, dst *net.IP, ttl, seq int) {
	buf := newIcmpData(src, dst, 8, ttl, seq, p.ID)
	p.conn.WriteTo(buf, nil)
}

func (p *Pinger) handleIncoming(d []byte) {
	now := time.Now().UnixNano()

	ip := layers.IPv4{}
	udp := layers.UDP{}
	icmp := layers.ICMPv4{}
	payload := gopacket.Payload{}
	decoded := []gopacket.LayerType{}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip, &icmp, &udp, &payload)

	err := parser.DecodeLayers(d, &decoded)
	if err != nil {
		log.Println("error decoding:", err)
		return
	}

	for _, layerType := range decoded {
		switch layerType {
		case layers.LayerTypeIPv4:
			if ip.DstIP.String() != p.conn.LocalAddr().String() {
				log.Println("warn: icmp response with wrong dst")
				return
			}
			if ip.SrcIP.String() != p.host {
				log.Println("warn: icmp response with wrong src")
				return
			}
		case layers.LayerTypeUDP:
			// what's here? XXX
		case layers.LayerTypeICMPv4:
			if icmp.Id != uint16(p.ID) {
				log.Println("warn: icmp response with wrong ID")
				return
			}
			// XXX what's the payload here??
			// log.Println(icmp.Payload)
		}
	}

	interval := p.getInterval(now, int(icmp.Seq))
	rtt := float32(interval/time.Microsecond) / 1000
	log.Printf("reply from %s: icmp_seq=%d ttl=%d time=%.1f ms", ip.SrcIP, icmp.Seq, ip.TTL, rtt)
	p.stats <- st{rtt, ip.TTL}

}

func (p *Pinger) getInterval(now int64, seq int) time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return time.Duration(now - p.ts[seq])
}

func newIcmpData(src, dest *net.IP, typeCode, ttl, seq, id int) (data []byte) {
	ip := &layers.IPv4{}
	ip.Version = 4
	ip.Protocol = layers.IPProtocolICMPv4
	ip.SrcIP = *src
	ip.DstIP = *dest

	ip.Length = 20
	ip.TTL = uint8(ttl)

	icmp := &layers.ICMPv4{}
	icmp.TypeCode = layers.ICMPv4TypeCode(uint16(typeCode) << 8)
	icmp.Id = uint16(id)
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
*/
