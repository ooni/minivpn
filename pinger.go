package main

import (
	"github.com/kalikaneko/minivpn/vpn"
	"log"
	//	"time"
)

func newPinger(c *vpn.Client) pinger {
	// XXX get it from opts, via args
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
	ip := p.c.GetTunnelIP()
	log.Println("Sending PING from", ip)
}

func (p pinger) handleIncoming(d []byte) {
	log.Println(">>> RECEIVED PING DATA", d)
	// XXX ...
}
