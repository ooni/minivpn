package main

import (
	"github.com/kalikaneko/minivpn/vpn"
	"log"
	//	"time"
)

func newPinger(c *vpn.Client) pinger {
	return pinger{c: c}
}

type pinger struct {
	c  *vpn.Client
	dc chan []byte
}

func (p pinger) InitConsumer() {
	p.dc = p.c.GetDataChannel()
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

func (p pinger) handleIncoming(d []byte) {
	log.Println(">>> RECEIVED PING DATA", d)
}
