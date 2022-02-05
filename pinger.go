package main

import (
	//	"encoding/binary"
	"encoding/hex"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kalikaneko/minivpn/vpn"
	//"bytes"
	//"golang.org/x/net/icmp"
	//"golang.org/x/net/ipv4"
	"log"
	"net"
	"os"
	//	"time"
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

	//log.Println(buf)
	log.Println("len:", len(buf))
	p.c.SendData(buf)
	// Y U NO REPLY??
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

	//now := time.Now().UnixNano()
	//var payload = make([]byte, 8)
	//binary.LittleEndian.PutUint64(payload, uint64(now))
	// I'm reading 28 bytes in the python impl, so that probl. means no payload
	var payload = []byte("")

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, opts, ip, icmp, gopacket.Payload(payload))

	// DEBUG -- XXX hardcoding the ping data from the python implementation ------------
	//hc := "4500001c00010000400160c70a080002080808080800f7fb00000000"
	hc := "4500001c00010000400160c70a080002080808080800f7ff00000000"
	res, _ := hex.DecodeString(hc)

	log.Println("buf:", buf)
	log.Println()
	log.Println("res:", res)
	log.Printf("res: %x\n", res)
	return res
	// ---------------------------------------------------------------------------------

	// wtf
	//return buf.Bytes()
}

/*
func serialize(ipLayer *layers.IPv4) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	err := ipLayer.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: false, ComputeChecksums: true})
	if err != nil {
		return nil, err
	}

	var buf2 bytes.Buffer
	buf2.Write(buf.Bytes())
	buf2.Write(ipLayer.Payload)

	return buf2.Bytes(), nil
}
*/

// Make a new ICMP message
// ...
// https://stackoverflow.com/questions/59985676/sending-udp-packets-to-127-0-0-1-with-gopacket
// https://stackoverflow.com/questions/59989003/golang-icmp-packet-sending
// ...
/*
	ip := layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolUDP,
	}
	log.Println("ip:", ip)
		m := icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{
				ID: os.Getpid() & 0xffff, Seq: 1, //<< uint(seq), // TODO
				Data: []byte(""),
			},
		}
		b, err := m.Marshal(nil)
		if err != nil {
			//return dst, 0, err
			log.Println("ERROR", err)
			return
		}
		log.Println(b)
*/
