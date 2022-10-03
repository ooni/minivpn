package vpn

//
// Reliability Layer for OpenVPN.
//
// From https://build.openvpn.net/doxygen/group__reliable.html:
//
// The Reliability Layer is part of OpenVPN's control channel. It provides a
// reliable and sequential transport mechanism for control channel messages
// between OpenVPN peers. This module forms the interface between the External
// Multiplexer and the Control Channel TLS module.
//
// This is especially important when OpenVPN is configured to communicate over
// UDP, because UDP does not offer a reliable and sequential transport. OpenVPN
// endpoints can also communicate over TCP which does provide a reliable and
// sequential transport. In both cases, using UDP or TCP as an external
// transport, the internal Reliability Layer is active.
//
// This file is based on the reliable_udp implementation by glacjay:
// https://github.com/glacjay/govpn

import (
	"fmt"
	"math"
	"net"
	"time"

	"github.com/apex/log"
)

const (
	reliableRecvCacheSize = 8
	reliableSendACKCount  = 4
	desistTimeSeconds     = 60
)

// reliableTransporter is a transport that implements OpenVPN reliability.
// layer.
type reliableTransporter interface {
	start()
	stop()
}

type outgoingPacket struct {
	p    *packet
	conn net.Conn
}

// reliableTransport implements reliableTransporter.
type reliableTransport struct {
	session *session
	//conn    net.Conn

	stopChan        chan struct{}
	failChan        <-chan time.Time
	doneHandshake   chan struct{}
	ctrlSendChan    chan *outgoingPacket
	receivingPID    packetID
	receivedPackets [reliableRecvCacheSize]*packet
	waitingACKs     map[packetID]chan<- struct{}
	acks            ackArray
}

var _ reliableTransporter = &reliableTransport{}

// newReliableTransport accepts a channel of pointer to packets, and returns
// a pointer to a new reliableTransport.
func newReliableTransport(session *session, controlReceiveChan <-chan *packet) *reliableTransport {
	rt := &reliableTransport{
		session:       session,
		stopChan:      make(chan struct{}),
		failChan:      time.After(time.Second * desistTimeSeconds),
		doneHandshake: make(chan struct{}),
		ctrlSendChan:  make(chan *outgoingPacket),
		//ctrlRecvChan:  controlReceiveChan,
		waitingACKs: make(map[packetID]chan<- struct{}),
	}
	rt.start()
	return rt
}

func (r *reliableTransport) start() {
	go func() {
		for {
			if !r.loop() {
				break
			}
		}
	}()
}

func (r *reliableTransport) stop() {
	r.stopChan <- struct{}{}
}

func (rt *reliableTransport) loop() bool {
	/*
	 var ackTimeout <-chan time.Time
	 if len(rt.acks) > 0 {
	 	ackTimeout = time.After(time.Microsecond)
	 }
	*/
	select {
	case <-rt.stopChan:
		return false
	case <-rt.failChan:
		log.Errorf("cannot negotiate with peer within %s seconds", desistTimeSeconds)
		return false
	case <-rt.doneHandshake:
		rt.failChan = nil

	case packet := <-rt.ctrlSendChan:
		rt.waitingACKs[packet.p.id] = rt.sendControlPacket(packet.p, packet.conn)

		/*
		 case <-ackTimeout:
		 	// TODO is this sending empty acks? need a conn to send in that case
		 	//rt.sendControlPacket(&packet{opcode: pACKV1})
		*/
	}
	return true
}

func (r *reliableTransport) processACK(p *packet) {
	packet, err := parseControlPacket(p)
	if err != nil {
		fmt.Println("cannot parse", err)
		return
	}
	for _, ack := range packet.acks {
		if _, ok := r.waitingACKs[ack]; ok {
			r.waitingACKs[ack] <- struct{}{}
			delete(r.waitingACKs, ack)
		}
	}
}

/// refactor -------------------------------------------

// UpdateLastACK will update the internal variable for the last acknowledged
// packet to the passed packetID, only if packetID is greater than the lastACK.
func (r *reliableTransport) UpdateLastACK(newPacketID packetID) error {
	r.session.mu.Lock()
	defer r.session.mu.Unlock()
	if r.session.lastACK == math.MaxUint32 {
		return errExpiredKey
	}
	if r.session.lastACK != 0 && newPacketID <= r.session.lastACK {
		logger.Warnf("tried to write ack %d; last was %d", newPacketID, r.session.lastACK)
	}
	r.session.lastACK = newPacketID
	return nil
}

// TODO this method is wrong. It needs to check if the difference between the
// incoming packet is greater than cachesize, and drop in that case.

// isNextPacket returns true if the packetID is the next integer
// from the last acknowledged packet.
func (r *reliableTransport) isNextPacket(p *packet) bool {
	panicIfTrue(p == nil, "nil packet")
	r.session.mu.Lock()
	defer r.session.mu.Unlock()
	next := p.id-r.session.lastACK == 1
	return next
}

// end refactor -----------------------------------------------

// sendControlPacket writes the passed packet over the given connection, and
// will schedule retries if the packet is not an ACK packet. It returns a
// struct{} chan that is used to keep track of the awaiting packets that we
// need ACKs for.
func (r *reliableTransport) sendControlPacket(packet *packet, conn net.Conn) chan<- struct{} {
	nACK := len(r.acks)
	if nACK > reliableSendACKCount {
		nACK = reliableSendACKCount
	}
	packet.acks = make(ackArray, nACK)
	copy(packet.acks, r.acks)

	buf := packet.Bytes()
	buf = maybeAddSizeFrame(conn, buf)

	_, err := conn.Write(buf)
	if err != nil {
		log.Errorf("cannot send packet %v", err)
	}

	r.acks = r.acks[nACK:]
	if packet.opcode != pACKV1 {
		packet.acks = nil
		return r.startRetrySendControlPacket(conn, buf, packet.id)
	}
	return nil
}

func (rt *reliableTransport) startRetrySendControlPacket(conn net.Conn, buf []byte, id packetID) chan<- struct{} {
	stopChan := make(chan struct{})
	go func() {
		elapsedSeconds := 0
		for i := 1; elapsedSeconds < desistTimeSeconds; i *= 2 {
			elapsedSeconds += 1
			select {
			case <-stopChan:
				return
			case <-time.After(time.Duration(i) * time.Second):
				_, err := conn.Write(buf)
				if err != nil {
					// TODO write to an error channel that
					// can bubble up.
					log.Errorf("cannot send packet: %v", err)
				}

			}
		}
		log.Errorf("Giving up after %d seconds: %v", desistTimeSeconds, id)
	}()
	return stopChan
}
