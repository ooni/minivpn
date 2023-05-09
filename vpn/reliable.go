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
	"bytes"
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
	// ErrBadConnNetwork indicates that the conn's network is neither TCP nor UDP.
	ErrBadConnNetwork           = errors.New("bad conn.Network value")
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
	Conn net.Conn

	session *session

	// errChan is where external objects can read from
	// to know that the reliable handshake failed.
	errChan chan error
	// failChan is triggered after timer expires.
	failChan <-chan time.Time
	// stopChan will stop the reliable transport.
	stopChan chan struct{}

	doneHandshake chan struct{}
	ctrlSendChan  chan *outgoingPacket
	tlsQueueChan  chan *packet
	tlsRecvBuf    bytes.Buffer
	bufReader     *bytes.Buffer

	receivingPID    packetID
	receivedPackets [reliableRecvCacheSize]*packet
	waitingACKs     map[packetID]chan<- struct{}
	acks            ackArray
	lastACK         packetID
	startOnce       sync.Once
}

var _ reliableTransporter = &reliableTransport{}

// newReliableTransport accepts a channel of pointer to packets, and returns
// a pointer to a new reliableTransport.
func newReliableTransport(session *session) *reliableTransport {
	buf := bytes.NewBuffer(nil)
	rt := &reliableTransport{
		session:       session,
		bufReader:     buf,
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
// TODO where is this used from??
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
		return true, fmt.Errorf("%w: %s", errBadInput, "packet diff > len received")
	}
	return r.receivedPackets[diff] != nil, nil
}

func (r *reliableTransport) TrackIncomingPacket(p *packet) {
	fmt.Println(">>> tracking", p.id)
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
			// TODO -- pass this to tls
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
	if r.lastACK == math.MaxUint32 {
		return errExpiredKey
	}
	if r.lastACK != 0 && newPacketID <= r.lastACK {
		logger.Warnf("tried to write ack %d; last was %d", newPacketID, r.lastACK)
		return errBadACK
	}
	r.lastACK = newPacketID
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
				// we have received an ack here,
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

// handleIncomingPacket parses the received bytes, and performs checks to catch out-of-order
// packets or packets that arrive out of the receiving window. It returns the
// parsed packet and any error if the operation could not be completed.
func (rt *reliableTransport) handleIncomingPacket(buf []byte) (*packet, error) {
	var p *packet
	var err error
	if p, err = parsePacketFromBytes(buf); err != nil {
		return nil, err
	}
	if p.isACK() {
		rt.processACK(p)
		return nil, nil
	}
	if rt.isPacketTooFar(p) {
		// drop
		logger.Warnf("Packet too far: %v", p.id)
		return nil, nil
	}
	if dup, err := rt.isDuplicatedPacket(p); dup || err != nil {
		// drop
		if err != nil {
			logger.Warnf("Error comparing packets: %v", err)
		} else {
			logger.Warnf("Dup: %v", p.id)
		}
		return nil, nil
	}
	rt.TrackIncomingPacket(p)
	return p, nil
}

// implementation of net.Conn over the reliable transport
// TODO: use pipe for underlying Conn

func (rt *reliableTransport) Close() error                       { return nil }
func (rt *reliableTransport) LocalAddr() net.Addr                { return nil }
func (rt *reliableTransport) RemoteAddr() net.Addr               { return nil }
func (rt *reliableTransport) SetDeadline(t time.Time) error      { return nil }
func (rt *reliableTransport) SetReadDeadline(t time.Time) error  { return nil }
func (rt *reliableTransport) SetWriteDeadline(t time.Time) error { return nil }

func (rt *reliableTransport) Read(b []byte) (n int, err error) {
	switch len(rt.tlsQueueChan) {
	case 0:
		panicIfTrue(rt.Conn == nil, "nil conn")
		buf, err := readPacket(rt.Conn)
		if err != nil {
			logger.Errorf("cannot read packet: %v", err)
			return 0, err
		}
		rt.handleIncomingPacket(buf)
		return 0, nil
	default:
		p := <-rt.tlsQueueChan
		if p == nil || err != nil {
			return 0, err
		}

		fmt.Println("sending ack")
		if err := sendACKFn(rt.Conn, rt, p.id); err != nil {
			return 0, err
		}
		return writeAndReadFromBufferFn(rt.bufReader, b, p.payload)
	}

}

// writeAndReadPayloadFromBuffer writes a given payload to a buffered reader, and returns
// a read from that same buffered reader into the passed byte array. it returns both an integer
// denoting the amount of bytes read, and any error during the operation.
func writeAndReadFromBuffer(bb *bytes.Buffer, b []byte, payload []byte) (int, error) {
	panicIfTrue(bb == nil, "nil buffer")
	bb.Write(payload)
	return bb.Read(b)
}

var writeAndReadFromBufferFn = writeAndReadFromBuffer

func (rt *reliableTransport) Write(b []byte) (n int, err error) {
	buf := make([]byte, len(b))
	copy(buf, b)
	p := &packet{
		opcode:  pControlV1,
		payload: buf,
	}
	id, err := rt.session.LocalPacketID()
	p.id = id
	p.localSessionID = rt.session.LocalSessionID
	payload := p.Bytes()
	out := maybeAddSizeFrame(rt.Conn, payload)
	_, err = rt.Conn.Write(out)
	return len(b), err
}
