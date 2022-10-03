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
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	"github.com/apex/log"
)

const (
	reliableRecvCacheSize = 8
	reliableSendACKCount  = 4
	desistTimeSeconds     = 60
)

var (
	ErrReliableHandshakeTimeout = errors.New("reliable handshake gave up")
	errBadACK                   = errors.New("bad ack number")
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

	// errChan is where external objects can read from
	// to know that the reliable handshake failed.
	errChan chan error
	// failChan is triggered after timer expires.
	failChan <-chan time.Time
	// stopChan will stop the reliable transport.
	stopChan chan struct{}

	doneHandshake   chan struct{}
	ctrlSendChan    chan *outgoingPacket
	tlsQueueChan    chan *packet
	receivingPID    packetID
	receivedPackets [reliableRecvCacheSize]*packet
	waitingACKs     map[packetID]chan<- struct{}
	acks            ackArray
	startOnce       sync.Once
}

var _ reliableTransporter = &reliableTransport{}

// newReliableTransport accepts a channel of pointer to packets, and returns
// a pointer to a new reliableTransport.
func newReliableTransport(session *session) *reliableTransport {
	rt := &reliableTransport{
		session:       session,
		stopChan:      make(chan struct{}, 1),
		errChan:       make(chan error, 1),
		failChan:      time.After(time.Second * desistTimeSeconds),
		doneHandshake: make(chan struct{}),
		tlsQueueChan:  make(chan *packet, 100),
		ctrlSendChan:  make(chan *outgoingPacket),
		waitingACKs:   make(map[packetID]chan<- struct{}),
	}
	rt.start()
	return rt
}

func (r *reliableTransport) start() {
	go func() {
		r.startOnce.Do(func() {
			for {
				if !r.loop() {
					break
				}
			}
		})
	}()
}

func (r *reliableTransport) stop() {
	r.stopChan <- struct{}{}
}

func (r *reliableTransport) loop() bool {
	select {
	case <-r.stopChan:
		return false
	case <-r.failChan:
		log.Errorf("cannot negotiate with peer within %d seconds", desistTimeSeconds)
		r.errChan <- ErrReliableHandshakeTimeout
		return false
	case <-r.doneHandshake:
		r.failChan = nil
	case packet := <-r.ctrlSendChan:
		r.waitingACKs[packet.p.id] = r.sendControlPacket(packet.p, packet.conn)
	}
	return true
}

// queuePacketToSend sends the passed pointer to outgoingPacket to the internal
// control send channel.
func (r *reliableTransport) queuePacketToSend(p *outgoingPacket) {
	r.ctrlSendChan <- p
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

// isPacketTooFar returns true if the received packet ID is beyond the current
// receiving PID plus the reliable receiving cache size.
func (r *reliableTransport) isPacketTooFar(p *packet) bool {
	diff := p.id - r.receivingPID
	return int(diff) >= reliableRecvCacheSize
}

// isDuplicatedPacket returns true when we already have an entry for a packet
// this far in the receiving buffer.
func (r *reliableTransport) isDuplicatedPacket(p *packet) (bool, error) {
	diff := p.id - r.receivingPID
	if len(r.receivedPackets) < int(diff) {
		// TODO this probably should return an error instead
		return true, fmt.Errorf("%w: %s", errBadInput, "packet diff > len received")
	}
	return r.receivedPackets[diff] != nil, nil
}

func (r *reliableTransport) TrackIncomingPacket(p *packet) {
	var diff packetID
	// TODO(ainghazal): need to test this check more thoroughly
	if p.id == 0 && r.receivingPID == 0 {
		// nothing
	} else {
		diff = p.id - r.receivingPID - 1
		if int(diff) > len(r.receivedPackets)-1 {
			logger.Warnf("wrong packet id diff: %d\n", int(diff))
			return
		}
	}
	r.receivedPackets[diff] = p
	if p.isControlV1() {
		i := 0
		for r.receivedPackets[i] != nil {
			r.tlsQueueChan <- r.receivedPackets[i]
			i++
			r.receivingPID++
		}
		copy(r.receivedPackets[:reliableRecvCacheSize-i], r.receivedPackets[i:])
	}
}

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
		return errBadACK
	}
	r.session.lastACK = newPacketID
	return nil
}

// sendControlPacket writes the passed packet over the given connection, and
// will schedule retries if the packet is not an ACK packet. It returns a
// struct{} chan (the stop channel for this particular retry loop) that is used
// to keep track of the awaiting packets that we need ACKs for.
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
		log.Errorf("send control: cannot send packet %v", err)
		// TODO(ainghazal: it does not make sense to keep retrying if the error is
		// non-recoverable. But perhaps we want to pick only a subset of these errors
		// (writing to a closed connection is one common one we want to fail upon)
		// I'm leaving it like it is for the time being beacause it
		// seems to behave well.
		r.stop()
		return nil
	}

	r.acks = r.acks[nACK:]
	if packet.opcode != pACKV1 {
		packet.acks = nil
		return r.startRetrySendControlPacket(conn, buf, packet.id)
	}
	return nil
}

// startRetrySendControlPacket initiates a loop in which we retry sending the
// passed control packet, for a maximum of desistTimeSeconds time. It returns a
// chan of struct{} that can be used to stop the retry loop.
func (rt *reliableTransport) startRetrySendControlPacket(conn net.Conn, buf []byte, id packetID) chan<- struct{} {
	stopChan := make(chan struct{})
	go func() {
		elapsedSeconds := 0
		for i := 1; elapsedSeconds < desistTimeSeconds; i *= 2 {
			elapsedSeconds += 1
			select {
			case <-stopChan:
				// we probably have received an ack here,
				// so stop resending.
				return
			case <-time.After(time.Duration(i) * time.Second):
				_, err := conn.Write(buf)
				if err != nil {
					// TODO write to an error channel that
					// can bubble up?
					//break
					log.Errorf("cannot send packet: %v", err)
					rt.stop()
					return
				}

			}
		}
		log.Errorf("Giving up after %d seconds: %v", desistTimeSeconds, id)
	}()
	return stopChan
}
