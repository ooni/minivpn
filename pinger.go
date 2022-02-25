package main

// Portions of this file are modified after github.com/go-ping
// Copyright (c) 2016 Cameron Sparr and contributors.
// Copyright (c) 2022 Ain Ghazal

// TODO
// [ ] optional: return json output
// [ ] define DataHandler / DataProducer interface better
// [ ] mark concrete functions that are taken from go-ping

import (
	"encoding/binary"
	"log"
	"math"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/ainghazal/minivpn/vpn"
)

// NewPinger returns a pointer to a Pinger struct configured to handle data from a
// vpn.Client. It needs host and count as parameters, and also accepts a done
// channel in which termination of the measurement series will be notified.
func NewPinger(c *vpn.Client, host string, count uint32, done chan bool) *Pinger {
	// TODO validate host ip / domain
	id := os.Getpid() & 0xffff
	ts := make(map[int]int64)
	stats := make(chan st, int(count))
	return &Pinger{
		c:        c,
		host:     host,
		ts:       ts,
		Count:    int(count),
		Interval: 1,
		ID:       id,
		TTL:      64,
		done:     done,
		stats:    stats,
	}
}

type st struct {
	rtt float32
	ttl uint8
}

type Pinger struct {
	c     *vpn.Client
	dc    chan []byte
	done  chan bool
	stats chan st
	st    []st
	// stats mutex
	mu sync.Mutex
	// send payload mutex
	pmu sync.Mutex

	host string

	Count    int
	Interval time.Duration
	ID       int

	ts map[int]int64

	PacketsSent int
	PacketsRecv int
	TTL         int
}

func (p *Pinger) Run() {
	p.dc = p.c.DataChannel()
	go p.consumeData()
	for i := 0; i < p.Count; i++ {
		go p.SendPayload(i)
		if i < p.Count-1 {
			time.Sleep(time.Second * 1)
		} else {
			time.Sleep(time.Millisecond * 200)
		}

	}
	go func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		for i := 0; i < p.Count; i++ {
			st := <-p.stats
			p.st = append(p.st, st)
			p.PacketsRecv += 1
		}
		// alternatively, catch SIGINT here and do this too:
		p.Shutdown()
	}()
}

func (p *Pinger) Shutdown() {
	p.printStats()
	p.done <- true
}

func (p *Pinger) printStats() {
	log.Println("--- " + p.host + " ping statistics ---")
	loss := (p.PacketsRecv / p.PacketsSent) / 100
	var r []float32
	var sum, sd, min, max float32
	min = p.st[0].rtt
	for _, s := range p.st {
		r = append(r, s.rtt)
		sum += s.rtt
		if s.rtt < min {
			min = s.rtt
		}
		if s.rtt > max {
			max = s.rtt
		}
	}
	avg := float32(float32(sum) / float32(len(r)))
	for _, s := range p.st {
		sd += float32(math.Pow(float64(s.rtt-avg), 2))
	}
	sd = float32(math.Sqrt(float64(sd / float32(len(r)))))
	log.Printf("%d packets transmitted, %d received, %d%% packet loss", p.PacketsSent, p.PacketsRecv, loss)
	log.Printf("rtt min/avg/max/stdev = %.3f, %.3f, %.3f, %.3f ms", min, avg, max, sd)
}

func (p *Pinger) consumeData() {
	for i := 0; i < p.Count; i++ {
		select {
		case data := <-p.dc:
			go p.handleIncoming(data)
		}
	}
}

func (p *Pinger) SendPayload(s int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	src := p.c.TunnelIP()
	srcIP := net.ParseIP(src)
	dstIP := net.ParseIP(p.host)
	p.ts[s] = time.Now().UnixNano()
	go p.craftAndSendICMP(&srcIP, &dstIP, p.TTL, s)
	p.PacketsSent += 1
}

func (p *Pinger) craftAndSendICMP(src, dst *net.IP, ttl, seq int) {
	buf := newIcmpData(src, dst, 8, ttl, seq, p.ID)
	p.c.SendData(buf)
}

func (p *Pinger) handleIncoming(d []byte) {
	now := time.Now().UnixNano()
	var (
		ip      layers.IPv4
		udp     layers.UDP
		icmp    layers.ICMPv4
		payload gopacket.Payload
	)

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
			if ip.DstIP.String() != p.c.TunnelIP() {
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
