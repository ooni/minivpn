package vpn

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
)

//
// OpenVPN Multiplexer
//

/*

 From: https://community.openvpn.net/openvpn/wiki/SecurityOverview

 OpenVPN multiplexes the SSL/TLS session used for authentication and key
 exchange with the actual encrypted tunnel data stream. OpenVPN provides the
 SSL/TLS connection with a reliable transport layer (as it is designed to
 operate over). The actual IP packets, after being encrypted and signed with an
 HMAC, are tunnelled over UDP without any reliability layer. So if --proto udp
 is used, no IP packets are tunneled over a reliable transport, eliminating the
 problem of reliability-layer collisions -- Of course, if you are tunneling a
 TCP session over OpenVPN running in UDP mode, the TCP protocol itself will
 provide the reliability layer.

SSL/TLS -> Reliability Layer -> \
           --tls-auth HMAC       \
                                  \
                                   > Multiplexer ----> UDP
                                  /                    Transport
IP        Encrypt and HMAC       /
Tunnel -> using OpenSSL EVP --> /
Packets   interface.

This model has the benefit that SSL/TLS sees a reliable transport layer while
the IP packet forwarder sees an unreliable transport layer -- exactly what both
components want to see. The reliability and authentication layers are
completely independent of one another, i.e. the sequence number is embedded
inside the HMAC-signed envelope and is not used for authentication purposes.
*/

// muxer is the VPN transport multiplexer. The muxer:
// 1. is given access to the transport net.Conn (it owns it).
// 2. reads from the transport
// 3. holds references to a controler and a dataHandler implementer.
// 4. initializes and owns a session instance.
// 5. on reads, it routes data packets to the dataHandler implementer, and
//    control packets to the controler implementor.
type muxer struct {
	// a net.Conn that has access to the "wire" transport. this can represent
	// an UDP/TCP socket, or a net.Conn coming from a Pluggable Transport etc.
	conn net.Conn
	tls  net.Conn

	control   controlHandler
	data      dataHandler
	bufReader *bytes.Buffer

	session *session
	tunnel  *tunnel
}

// controlHandler manages the control "channel".
type controlHandler interface {
	Options() *Options
	InitTLS(net.Conn, *session) (net.Conn, error)
	SendHardReset(net.Conn, *session)
	// ...
}

// dataHandler manages the data "channel".
type dataHandler interface {
	SetupKeys(*dataChannelKey, *session) error
	WritePacket(net.Conn, []byte) (int, error)
	ReadPacket([]byte) ([]byte, error)
	// ...
}

// initialization

// Init initializes the muxer:
// 1. creates a new session,
// 2. initializes a controlHandler.
// TODO: refactor: newMuxer
func (m *muxer) Init(opt *Options) error {
	session, err := newSession()
	if err != nil {
		return err
	}
	m.session = session

	// TODO get the interface with an empty struct!!
	control := newControl(opt)
	m.control = control

	data, err := newDataFromOptions(opt, session)
	if err != nil {
		return err
	}
	m.data = data

	br := bytes.NewBuffer(nil)
	m.bufReader = br

	return nil
}

// handshake

func (m *muxer) Handshake() error {
	// 1. Conrol channel handshake: send reset, parse response
	if err := m.Reset(); err != nil {
		return err
	}

	// 2. tls handshake
	tls, err := m.control.InitTLS(m.conn, m.session)
	if err != nil {
		return err
	}
	m.tls = tls

	// 3. data init (auth, push, data initialization)
	if err := m.InitDataWithRemoteKey(); err != nil {
		return err
	}
	return nil
}

// Reset sends a hard-reset packet to the server, and waits for the server
// confirmation. It is the third step in an OpenVPN connection (out of five).
func (m *muxer) Reset() error {
	m.control.SendHardReset(m.conn, m.session)
	resp := m.readPacket()
	remoteSessionID, err := parseHardReset(resp)
	// here we could check if we have received a remote session id but
	// our session.remoteSessionID is != from all zeros
	if err != nil {
		return fmt.Errorf("%s: %w", ErrBadHandshake, err)
	}

	m.session.RemoteSessionID = remoteSessionID
	log.Printf("Learned remote session ID: %x\n", remoteSessionID.Bytes())

	// this id is (always?) 0, is the first packet we ack
	// TODO should I parse the packet id from server instead?
	sendACK(m.conn, m.session, uint32(0))
	return nil
}

// direct read

func (m *muxer) readPacket() []byte {
	switch m.conn.LocalAddr().Network() {
	case protoTCP.String():
		b, err := readPacketFromTCP(m.conn)
		if err != nil {
			log.Println("error reading", err.Error())
			return nil
		}
		return b
	default:
		// for UDP we don't need to parse size frames
		var r = make([]byte, 4096)
		n, err := m.conn.Read(r)
		if err != nil {
			log.Println("error reading", err.Error())
			return nil
		}
		data := r[:n]
		return data
	}
}

func readPacketFromTCP(conn net.Conn) ([]byte, error) {
	lenbuff := make([]byte, 2)

	if _, err := io.ReadFull(conn, lenbuff); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(lenbuff)
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// read and handle packet

// handleIncoming packet reads the next packet available in the underlying
// socket. It returns true if the packet was a data packet; otherwise it will
// process it but return false.
func (m *muxer) handleIncomingPacket() bool {
	data := m.readPacket()
	p := newPacketFromBytes(data)
	if p.isACK() {
		log.Println("Got ACK")
		return false
	}
	if p.isControl() {
		log.Println("Got control packet", len(data))
		// TODO pass it to contronHandler.
		// Here the server might be requesting us to reset, or to
		// re-key (but I keep ignoring that case for now).
		fmt.Println(hex.Dump(p.payload))
		return false
	}
	if !p.isData() {
		log.Printf("ERROR: unhandled data. (op: %d)\n", p.opcode)
		fmt.Println(hex.Dump(data))
		return false
	}
	// if bytes.Equal(payload, pingPayload) {
	// TODO isPing packet? => handleDataPing
	// TODO else...
	// return m.data.ReadPacket(data)
	// ...
	// so basically same thing that we do on tls transport:
	// 1. read
	// 2. is control? do something with that
	// 3. is data? decompress+decrypt, write to buffer, read from buffer
	// TODO pass the packet itself
	plaintext, err := m.data.ReadPacket(data)
	if err != nil {
		log.Println("bad decryption")
		// XXX I'm not sure returning false is the right thing to do here.
		return false
	}
	m.bufReader.Write(plaintext)
	return true
}

func (m *muxer) handleDataPing() error {
	log.Println("openvpn-ping, sending reply")
	m.data.WritePacket(m.conn, pingPayload)
	return nil
}

// tls channel reads

func (m *muxer) readTLSPacket() ([]byte, error) {
	data := make([]byte, 4096)
	_, err := m.tls.Read(data)
	return data, err
}

func (m *muxer) readRemoteKey() error {
	data, err := m.readTLSPacket()
	if err != nil {
		return err
	}
	if !isControlMessage(data) {
		fmt.Errorf("%w:%s", errBadControlMessage, "expected null header")
	}
	remoteKey, opts, err := readControlMessage(data)
	if err != nil {
		log.Println("ERROR: cannot parse control message")
	}
	key, err := m.session.ActiveKey()
	if err != nil {
		log.Println("ERROR: cannot get active key", err.Error())
		return err
	}
	key.addRemoteKey(remoteKey)
	tunnel, err := parseRemoteOptions(opts)
	if err != nil {
		return err
	}
	m.tunnel = tunnel
	return nil
}

func (m *muxer) readPushReply() error {
	reply, err := m.readTLSPacket()
	if err != nil {
		return err
	}

	if isBadAuthReply(reply) {
		return errBadAuth
	}

	if !isPushReply(reply) {
		return fmt.Errorf("%w:%s", errBadServerReply, "expected push reply")
	}

	ip := parsePushedOptions(reply)
	m.tunnel.ip = ip
	return nil
}

//
// write methods
//

// tls writes

// TODO: refactor: turn into a method in controlHandler or bring the other control write methods here.

func (m *muxer) sendPushRequest() {
	m.tls.Write(encodePushRequestAsBytes())
}

// InitDataWithRemoteKey initializes the internal data channel. To do that, it sends a
// control packet, parses the response, and derives the cryptographic material
// that will be used to encrypt and decrypt data through the tunnel. At the end
// of this exchange, the data channel is ready to be used.
func (m *muxer) InitDataWithRemoteKey() error {
	controlMessage, err := encodeControlMessage(m.session, m.control.Options())
	if _, err := m.tls.Write(controlMessage); err != nil {
		return err
	}

	err = m.readRemoteKey()
	log.Println("Key exchange complete")

	m.sendPushRequest()
	m.readPushReply()

	// now all that's left is "initializing" the data channel

	key0, err := m.session.ActiveKey()
	if err != nil {
		return err
	}

	err = m.data.SetupKeys(key0, m.session)
	if err != nil {
		return err
	}
	log.Println("Data initialization complete!")
	return nil
}

// TODO(ainghazal, bassosimone): it probably makes sense to return an error
// from read/write if the data channel is not initialized. Another option would
// be to read from a channel and block if there's nothing.

// Write sends bytes as encrypted packets in the data channel.
func (m *muxer) Write(b []byte) (int, error) {
	return m.data.WritePacket(m.conn, b)
}

// Read reads bytes after decrypting packets from the data channel.
func (m *muxer) Read(b []byte) (int, error) {
	for {
		if ok := m.handleIncomingPacket(); ok {
			break
		}
	}
	return m.bufReader.Read(b)
}

// convenience methods, perhaps expose the underlying tunnel struct

// TunnelIP returns the local IP that the server assigned us.
func (m *muxer) TunnelIP() string {
	return m.tunnel.ip
}

// TunMTU returns the tun-mtu value that the remote advertises.
func (m *muxer) TunMTU() int {
	return m.tunnel.mtu
}
