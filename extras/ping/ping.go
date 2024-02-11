// Package ping is a simple but powerful ICMP echo (ping) library.
// This file is a modification of one of the elements in the go-ping library.
// for the purposes of writing raw UDP packets over a VPN tunnel.
package ping

/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2016 Cameron Sparr and contributors.
 * Copyright (C) 2022 Ain Ghazal.
 */

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
)

const (
	timeSliceLength = 8
	trackerLength   = len(uuid.UUID{})
)

var (
	ipv4Proto = map[string]string{"icmp": "ip4:icmp", "udp": "udp4"}
	ipv6Proto = map[string]string{"icmp": "ip6:ipv6-icmp", "udp": "udp6"}

	errCannotWrite           = errors.New("cannot write")
	errCannotRead            = errors.New("cannot read")
	errCannotSetReadDeadline = errors.New("cannot set read readline")
	errBadPacket             = errors.New("bad packet")
)

// New returns a new Pinger struct pointer.  This function TAKES OWNERSHIP of
// the conn argument and closes it when Run terminates.
func New(addr string, conn net.Conn) *Pinger {
	b := make([]byte, 2)
	_, err := rand.Read(b)
	if err != nil {
		return &Pinger{}
	}
	id := binary.BigEndian.Uint16(b)
	firstUUID := uuid.New()
	var firstSequence = map[uuid.UUID]map[int]struct{}{}
	firstSequence[firstUUID] = make(map[int]struct{})
	return &Pinger{
		sharedConnection:  false,
		Target:            addr,
		Count:             -1,
		Interval:          time.Second,
		RecordReplies:     true,
		replies:           []PingReply{},
		Size:              timeSliceLength + trackerLength,
		Timeout:           time.Duration(math.MaxInt64),
		addr:              addr,
		done:              make(chan interface{}),
		id:                int(id),
		trackerUUIDs:      []uuid.UUID{firstUUID},
		ipaddr:            nil,
		ipv4:              false,
		network:           "ip",
		protocol:          "udp",
		awaitingSequences: firstSequence,
		TTL:               64,
		conn:              conn,
	}
}

// NewFromSharedConnection returns a new Pinger struct pointer.
// This function TAKES OWNERSHIP of the conn argument, BUT it DOES NOT CLOSE IT
// when Run terminates.
func NewFromSharedConnection(addr string, conn net.Conn) *Pinger {
	pinger := New(addr, conn)
	pinger.sharedConnection = true
	return pinger
}

type PingReply struct {
	Seq int
	TTL int
	Rtt time.Duration
}

// Pinger represents a packet sender/receiver.
type Pinger struct {
	// Target is a string with the target host IP.
	Target string

	// Interval is the wait time between each packet send. Default is 1s.
	Interval time.Duration

	// Timeout specifies a timeout before ping exits, regardless of how many
	// packets have been received.
	Timeout time.Duration

	// Count tells pinger to stop after sending (and receiving) Count echo
	// packets. If this option is not specified, pinger will operate until
	// interrupted.
	Count int

	// Debug runs in debug mode
	Debug bool

	// Number of packets sent
	PacketsSent int

	// Number of packets received
	PacketsRecv int

	// Number of duplicate packets received
	PacketsRecvDuplicates int

	// Round trip time statistics
	minRtt    time.Duration
	maxRtt    time.Duration
	avgRtt    time.Duration
	stdDevRtt time.Duration
	stddevm2  time.Duration
	statsMu   sync.RWMutex

	// If true, omit all output during measurement.
	Silent bool

	// If true, keep a record of replies of all received packets.
	// Set to false to avoid memory bloat for long running pings.
	RecordReplies bool

	replies []PingReply

	// OnSetup is called when Pinger has finished setting up the listening socket
	OnSetup func()

	// OnSend is called when Pinger sends a packet
	OnSend func(*Packet)

	// OnRecv is called when Pinger receives and processes a packet
	OnRecv func(*Packet)

	// OnFinish is called when Pinger exits
	OnFinish func(*Statistics)

	// OnDuplicateRecv is called when a packet is received that has already been received.
	OnDuplicateRecv func(*Packet)

	// Size of packet being sent
	Size int

	// Source is the source IP address
	Source string

	// Channel and mutex used to communicate when the Pinger should stop between goroutines.
	done chan interface{}
	lock sync.Mutex

	ipaddr *net.IPAddr
	addr   string

	// trackerUUIDs is the list of UUIDs being used for sending packets.
	trackerUUIDs []uuid.UUID

	ipv4     bool
	id       int
	sequence int
	// awaitingSequences are in-flight sequence numbers we keep track of to help remove duplicate receipts
	awaitingSequences map[uuid.UUID]map[int]struct{}
	// network is one of "ip", "ip4", or "ip6".
	network string
	// protocol is "icmp" or "udp".
	protocol string

	TTL int

	// conn is the connection we write to and read from
	conn net.Conn

	// sharedConnection will avoid closing the connection after we're done
	// if set to true.
	sharedConnection bool
}

type packet struct {
	bytes  []byte
	nbytes int
	ttl    int
}

// Packet represents a received and processed ICMP echo packet.
type Packet struct {
	// Rtt is the round-trip time it took to ping.
	Rtt time.Duration

	// IPAddr is the address of the host being pinged.
	IPAddr *net.IPAddr

	// Addr is the string address of the host being pinged.
	Addr string

	SrcIP *net.IP

	// NBytes is the number of bytes in the message.
	Nbytes int

	// Seq is the ICMP sequence number.
	Seq int

	// TTL is the Time To Live on the packet.
	Ttl int

	// ID is the ICMP identifier.
	ID int

	// Data is the packet payload
	Data []byte
}

// Statistics represent the stats of a currently running or finished
// pinger operation.
type Statistics struct {
	// PacketsRecv is the number of packets received.
	PacketsRecv int

	// PacketsSent is the number of packets sent.
	PacketsSent int

	// PacketsRecvDuplicates is the number of duplicate responses there were to a sent packet.
	PacketsRecvDuplicates int

	// PacketLoss is the percentage of packets lost.
	PacketLoss float64

	// IPAddr is the address of the host being pinged.
	IPAddr *net.IPAddr

	// Addr is the string address of the host being pinged.
	Addr string

	Replies []PingReply

	// MinRtt is the minimum round-trip time sent via this pinger.
	MinRtt time.Duration

	// MaxRtt is the maximum round-trip time sent via this pinger.
	MaxRtt time.Duration

	// AvgRtt is the average round-trip time sent via this pinger.
	AvgRtt time.Duration

	// StdDevRtt is the standard deviation of the round-trip times sent via
	// this pinger.
	StdDevRtt time.Duration
}

func (p *Pinger) updateStatistics(pkt *Packet) {
	p.statsMu.Lock()
	defer p.statsMu.Unlock()

	p.PacketsRecv++
	if p.RecordReplies {
		reply := PingReply{
			// Here we're normalizing to 1-indexed arrays, just
			// like the ping utility.
			Seq: int(pkt.Seq) + 1,
			TTL: pkt.Ttl,
			Rtt: pkt.Rtt,
		}
		p.replies = append(p.replies, reply)

	}

	if p.PacketsRecv == 1 || pkt.Rtt < p.minRtt {
		p.minRtt = pkt.Rtt
	}

	if pkt.Rtt > p.maxRtt {
		p.maxRtt = pkt.Rtt
	}

	pktCount := time.Duration(p.PacketsRecv)
	// welford's online method for stddev
	// https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance#Welford's_online_algorithm
	delta := pkt.Rtt - p.avgRtt
	p.avgRtt += delta / pktCount
	delta2 := pkt.Rtt - p.avgRtt
	p.stddevm2 += delta * delta2

	p.stdDevRtt = time.Duration(math.Sqrt(float64(p.stddevm2 / pktCount)))
}

// Run runs the pinger. Accepts a single argument that is a Context. This is a
// blocking function that will exit when it's done (or when the context expires).
// If Count or Interval are not specified, it will run continuously until
// it is interrupted or the context expires.
func (p *Pinger) Run(ctx context.Context) (err error) {
	errch := make(chan error, 1)
	go func() {
		if p.Size < timeSliceLength+trackerLength {
			errch <- fmt.Errorf("size %d is less than minimum required size %d", p.Size, timeSliceLength+trackerLength)
		}
		errch <- p.run(p.conn)
	}()
	select {
	case err = <-errch:
	case <-ctx.Done():
		err = ctx.Err()
	}
	return
}

func (p *Pinger) run(conn net.Conn) error {
	if !p.sharedConnection {
		defer p.conn.Close()
	}
	defer p.finish()
	if p.Count <= 0 {
		return nil
	}

	recv := make(chan *packet, p.Count)
	defer close(recv)

	if handler := p.OnSetup; handler != nil {
		handler()
	}

	var g errgroup.Group

	g.Go(func() error {
		defer p.Stop()
		return p.runLoop(recv)
	})

	g.Go(func() error {
		defer p.Stop()
		return p.recvICMP(recv)
	})

	return g.Wait()
}

func (p *Pinger) runLoop(recvCh <-chan *packet) error {
	timeout := time.NewTicker(p.Timeout)
	interval := time.NewTicker(p.Interval)
	defer func() {
		interval.Stop()
		timeout.Stop()
	}()

	src := p.conn.LocalAddr().String()
	srcIP := net.ParseIP(src)
	dstIP := net.ParseIP(p.Target)

	for {
		select {
		case <-p.done:
			return nil

		case <-timeout.C:
			return nil

		case r := <-recvCh:
			err := p.processPacket(r)
			if err != nil {
				continue
			}

		case <-interval.C:
			if p.Count > 0 && p.PacketsSent >= p.Count {
				interval.Stop()
				continue
			}
			currentUUID := p.getCurrentTrackerUUID()

			icmpPacket := newIcmpData(&srcIP, &dstIP, 8, p.TTL, p.PacketsSent, p.id, currentUUID)
			_, err := p.conn.Write(icmpPacket)
			if err != nil {
				return fmt.Errorf("%w: %s", errCannotWrite, err)
			}

			// mark this sequence as in-flight
			p.awaitingSequences[currentUUID][p.PacketsSent] = struct{}{}
			p.PacketsSent++

		}
		if p.Count > 0 && p.PacketsRecv >= p.Count {
			p.done <- true
			return nil
		}
	}
}

// Stop stops the pinger run.
func (p *Pinger) Stop() {
	p.lock.Lock()
	defer p.lock.Unlock()

	open := true
	select {
	case _, open = <-p.done:
	default:
	}

	if open {
		close(p.done)
	}
}

func (p *Pinger) finish() {
	handler := p.OnFinish
	if handler != nil {
		s := p.Statistics()
		handler(s)
	}
}

// Statistics returns the statistics of the pinger. This can be run while the
// pinger is running or after it is finished. OnFinish calls this function to
// get its finished statistics.
func (p *Pinger) Statistics() *Statistics {
	p.statsMu.RLock()
	defer p.statsMu.RUnlock()
	sent := p.PacketsSent
	loss := float64(sent-p.PacketsRecv) / float64(sent) * 100
	s := Statistics{
		PacketsSent:           sent,
		PacketsRecv:           p.PacketsRecv,
		PacketsRecvDuplicates: p.PacketsRecvDuplicates,
		PacketLoss:            loss,
		Replies:               p.replies,
		Addr:                  p.addr,
		IPAddr:                p.ipaddr,
		MaxRtt:                p.maxRtt,
		MinRtt:                p.minRtt,
		AvgRtt:                p.avgRtt,
		StdDevRtt:             p.stdDevRtt,
	}
	return &s
}

type expBackoff struct {
	baseDelay time.Duration
	maxExp    int64
	c         int64
}

func (b *expBackoff) Get() time.Duration {
	if b.c < b.maxExp {
		b.c++
	}
	r, err := rand.Int(rand.Reader, big.NewInt(1<<b.c))
	if err != nil {
		r = big.NewInt(b.c)
	}

	return b.baseDelay * time.Duration(r.Uint64())
}

func newExpBackoff(baseDelay time.Duration, maxExp int64) expBackoff {
	return expBackoff{baseDelay: baseDelay, maxExp: maxExp}
}

func (p *Pinger) recvICMP(recv chan<- *packet) error {
	assert(p.conn != nil, "not initialized")

	// Start by waiting for 100 µs, and increment until a 10e3 multiplier
	expBackoff := newExpBackoff(100*time.Microsecond, 10)
	delay := expBackoff.Get()

	for {
		select {
		case <-p.done:
			return nil
		default:
			if p.PacketsRecv >= p.Count {
				return nil
			}
			buf := make([]byte, 512)
			if err := p.conn.SetReadDeadline(time.Now().Add(delay)); err != nil {
				return fmt.Errorf("%w: %s", errCannotSetReadDeadline, err)
			}
			n, err := p.conn.Read(buf)
			if err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					// Read timeout
					delay = expBackoff.Get()
					continue
				}
				return fmt.Errorf("%w: %s", errCannotRead, err)
			}

			select {
			case <-p.done:
				return nil
			case recv <- &packet{bytes: buf, nbytes: n}:
			}
		}
	}
}

// getPacketUUID scans the tracking slice for matches.
func (p *Pinger) getPacketUUID(pkt []byte) (*uuid.UUID, error) {
	var packetUUID uuid.UUID
	err := packetUUID.UnmarshalBinary(pkt[timeSliceLength : timeSliceLength+trackerLength])
	if err != nil {
		return nil, fmt.Errorf("error decoding tracking UUID: %w", err)
	}

	for _, item := range p.trackerUUIDs {
		if item == packetUUID {
			return &packetUUID, nil
		}
	}
	return nil, nil
}

// getCurrentTrackerUUID grabs the latest tracker UUID.
func (p *Pinger) getCurrentTrackerUUID() uuid.UUID {
	return p.trackerUUIDs[len(p.trackerUUIDs)-1]
}

func (p *Pinger) processPacket(recv *packet) error {
	pkt := p.parseEchoReply(recv.bytes)

	if pkt == nil || pkt.Data == nil {
		return nil
	}

	receivedAt := time.Now()
	if len(pkt.Data) < timeSliceLength+trackerLength {
		return fmt.Errorf("insufficient data received; got: %d %v", len(pkt.Data), pkt.Data)
	}

	pktUUID, err := p.getPacketUUID(pkt.Data)
	if err != nil || pktUUID == nil {
		return fmt.Errorf("%w: %s", errBadPacket, err)
	}

	timestamp := bytesToTime(pkt.Data[:timeSliceLength])
	pkt.Rtt = receivedAt.Sub(timestamp)

	if !p.Silent {
		fmt.Printf("reply from %s: icmp_seq=%d ttl=%d time=%.1f ms\n", pkt.SrcIP, pkt.Seq, pkt.Ttl, pkt.Rtt.Seconds()*1e3)
	}

	// If we've already received this sequence, ignore it.
	if _, inflight := p.awaitingSequences[*pktUUID][pkt.Seq]; !inflight {
		p.PacketsRecvDuplicates++
		if p.OnDuplicateRecv != nil {
			p.OnDuplicateRecv(pkt)
		}
		return nil
	}
	// remove it from the list of sequences we're waiting for so we don't get duplicates.
	delete(p.awaitingSequences[*pktUUID], pkt.Seq)
	p.updateStatistics(pkt)

	handler := p.OnRecv
	if handler != nil {
		handler(pkt)
	}

	return nil
}

// TODO(ainghazal): here I am using the naive way of doing timestamps, equivalent to "ping -U",
// but I expect it to be unstable under certain circumstances (high CPU load, GC pauses etc).
// It'd be a better idea to try to use kernel capabilities if available (need to research what's possible in osx/windows, possibly have a fallback to the naive way).
// in case we do see that load produces instability.
// https://coroot.com/blog/how-to-ping
func (p *Pinger) parseEchoReply(data []byte) *Packet {
	ip := layers.IPv4{}
	udp := layers.UDP{}
	icmp := layers.ICMPv4{}
	payload := gopacket.Payload{}
	decoded := []gopacket.LayerType{}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip, &icmp, &udp, &payload)

	err := parser.DecodeLayers(data, &decoded)
	if err != nil {
		return &Packet{}
	}

	for _, layerType := range decoded {
		switch layerType {
		case layers.LayerTypeIPv4:
			localAddr := p.conn.LocalAddr().String()

			if ip.DstIP.String() != localAddr {
				log.Println("warn: icmp response with wrong dst")
				return nil
			}
			if ip.SrcIP.String() != p.Target {
				log.Printf("warn: icmp response with wrong src: %s, expected: %s\n", ip.SrcIP.String(), p.Target)
				return nil
			}
		case layers.LayerTypeICMPv4:
			if icmp.Id != uint16(p.id) {
				log.Println("warn: icmp response with wrong ID")
				return nil
			}
		}
	}

	return &Packet{
		Nbytes: len(data),
		Seq:    int(icmp.Seq),
		SrcIP:  &ip.SrcIP,
		Addr:   p.addr,
		Ttl:    int(ip.TTL),
		ID:     p.id,
		Data:   payload.Payload(),
	}
}

// PrintStats outputs statistics similar to the ones produced by the ping command.
func (p *Pinger) PrintStats() {
	if p.PacketsSent == 0 {
		return
	}
	fmt.Println("--- " + p.Target + " ping statistics ---")
	fmt.Printf("%d packets transmitted, %d received, %d%% packet loss\n", p.PacketsSent, p.PacketsRecv, int(p.PacketLoss()))
	fmt.Printf("rtt min/avg/max/stdev = %v, %v, %v, %v\n", p.minRtt, p.avgRtt, p.maxRtt, p.stdDevRtt)
}

// PacketLoss calculates the ratio of packets lost (per cent).
func (p *Pinger) PacketLoss() int {
	ratio := float64(p.PacketsRecv) / float64(p.PacketsSent)
	return int(math.Round((1 - ratio) * 100))
}

// newIcmpData crafts an ICMP packet, using gopacket library.
func newIcmpData(src, dest *net.IP, typeCode, ttl, seq, id int, currentUUID uuid.UUID) (data []byte) {
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

	uuidEncoded, err := currentUUID.MarshalBinary()
	if err != nil {
		log.Printf("unable to marshal UUID binary: %s", err.Error())
		return []byte{}
	}
	payload := append(timeToBytes(time.Now()), uuidEncoded...)

	buf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buf, opts, ip, icmp, gopacket.Payload(payload))
	if err != nil {
		log.Println("error:", err)
	}

	return buf.Bytes()
}

// bytes to time deserializes a timestamp from a byte array, and returns a Time object.
func bytesToTime(b []byte) time.Time {
	var nsec int64
	for i := uint8(0); i < 8; i++ {
		nsec += int64(b[i]) << ((7 - i) * 8)
	}
	return time.Unix(nsec/1000000000, nsec%1000000000)
}

// timeToBytes converts a timestamp (a Time object accepted as the only argument)  to a byte array. Returns a byte array.
func timeToBytes(t time.Time) []byte {
	nsec := t.UnixNano()
	b := make([]byte, 8)
	for i := uint8(0); i < 8; i++ {
		b[i] = byte((nsec >> ((7 - i) * 8)) & 0xff)
	}
	return b
}

var seed int64 = time.Now().UnixNano()

// getSeed returns a goroutine-safe unique seed.
func getSeed() int64 {
	return atomic.AddInt64(&seed, 1)
}
