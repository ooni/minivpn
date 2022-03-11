/*
 * Copyright (C) 2022 Ain Ghazal. All Rights Reversed.
 */
package extras

import (
	"bytes"
	"fmt"
	"log"
	"math"
	"math/rand"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/ainghazal/minivpn/vpn"
)

const (
	// time, in seconds, before we timeout the connection used for sending an ECHO request.
	timeoutSeconds = 10
)

// NewPinger returns a pointer to a Pinger struct configured to handle data from a
// vpn.Client. It needs host and count as parameters, and also accepts a done
// channel in which termination of the measurement series will be notified.
func NewPinger(raw *vpn.RawDialer, host string, count int) *Pinger {
	// TODO validate host ip / domain
	id := os.Getpid() & 0xffff
	ts := make(map[int]int64)
	stats := make(chan st, int(count))
	return &Pinger{
		raw:      raw,
		host:     host,
		ts:       ts,
		Count:    int(count),
		Interval: 1,
		ID:       id,
		ttl:      64,
		stats:    stats,
	}
}

// st holds some stats about a single icmp
type st struct {
	rtt float32
	ttl uint8
}

// Pinger holds all the needed info to ping a target.
type Pinger struct {
	raw *vpn.RawDialer
	//conn  net.PacketConn // not needed
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

	packetsSent int
	packetsRecv int
	ttl         int
}

func (p *Pinger) printStats() {
	log.Println("--- " + p.host + " ping statistics ---")
	loss := (p.packetsRecv / p.packetsSent) / 100
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
	log.Printf("%d packets transmitted, %d received, %d%% packet loss", p.packetsSent, p.packetsRecv, loss)
	log.Printf("rtt min/avg/max/stdev = %.3f, %.3f, %.3f, %.3f ms", min, avg, max, sd)
}

func (p *Pinger) Run() {
	p.raw.Dial()
	d := vpn.NewDialer(p.raw)
	/* TODO
	   By using this Dial method, we lose access to TTL in the received packet.
	   I can either revert back to using the raw dialer (and reserve gvisor for TCP socks, http streams etc),
	   or try forking wireguard-go tun implementation. I believe this
	   discarded return parameter has the acces to the ttl via a
	   PacketConn:

	   https://git.zx2c4.com/wireguard-go/tree/tun/netstack/tun.go?id=ae6bc4dd64e1#n480
	*/
	socket, err := d.Dial("ping4", p.host)
	if err != nil {
		log.Panic(err)
	}

	for i := 0; i < p.Count; i++ {
		start := time.Now()
		requestPing := icmp.Echo{
			Seq:  rand.Intn(1 << 16),
			Data: []byte("hello filternet"), // get the start ts in here, as sbasso suggested
		}
		icmpBytes, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &requestPing}).Marshal(nil)
		socket.SetReadDeadline(time.Now().Add(time.Second * timeoutSeconds))

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
		log.Printf("Ping RTT: %v", time.Since(start))
		time.Sleep(1 * time.Second)

	}
}

// Stop prints ping statistics before quitting.
func (p *Pinger) Stop() {
	fmt.Println("should print stats now...")
	// p.printStats()
}
