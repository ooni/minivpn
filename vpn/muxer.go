package vpn

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
)

//
// OpenVPN Multiplexer
//

var (
	ErrBadHandshake     = errors.New("bad vpn handshake")
	ErrBadDataHandshake = errors.New("bad data handshake")
)

/*
 The vpnMuxer interface represents the VPN transport multiplexer.

 One important limitation of the current implementation at this moment is that
 the processing of incoming packets needs to be driven by reads from the user of
 the library. This means that if you don't do reads during some time, any packets
 on the control channel that the server sends us (e.g., openvpn-pings) will not
 be processed (and so, not acknowledged) until triggered by a muxer.Read().

 From the original documentation:
 https://community.openvpn.net/openvpn/wiki/SecurityOverview

 "OpenVPN multiplexes the SSL/TLS session used for authentication and key
 exchange with the actual encrypted tunnel data stream. OpenVPN provides the
 SSL/TLS connection with a reliable transport layer (as it is designed to
 operate over). The actual IP packets, after being encrypted and signed with an
 HMAC, are tunnelled over UDP without any reliability layer. So if --proto udp
 is used, no IP packets are tunneled over a reliable transport, eliminating the
 problem of reliability-layer collisions -- Of course, if you are tunneling a
 TCP session over OpenVPN running in UDP mode, the TCP protocol itself will
 provide the reliability layer."

 SSL/TLS -> Reliability Layer -> \
            --tls-auth HMAC       \
                                   \
                                    > Multiplexer ----> UDP/TCP
                                   /                    Transport
 IP        Encrypt and HMAC       /
 Tunnel -> using OpenSSL EVP --> /
 Packets   interface.

"This model has the benefit that SSL/TLS sees a reliable transport layer while
the IP packet forwarder sees an unreliable transport layer -- exactly what both
components want to see. The reliability and authentication layers are
completely independent of one another, i.e. the sequence number is embedded
inside the HMAC-signed envelope and is not used for authentication purposes."

*/

// muxer implements vpnMuxer
type muxer struct {

	// A net.Conn that has access to the "wire" transport. this can
	// represent an UDP/TCP socket, or a net.Conn coming from a Pluggable
	// Transport etc.
	conn net.Conn

	// After completing the TLS handshake, we get a tls transport that implements
	// net.Conn. All the control packets from that moment on are read from
	// and written to the tls Conn.
	tls net.Conn

	// control and data are the handlers for the control and data channels.
	// they implement the methods needed for the handshake and handling of
	// packets.
	control controlHandler
	data    dataHandler

	// bufReader is used to buffer data channel reads. We only write to
	// this buffer when we have correctly decrypted an incoming
	bufReader *bytes.Buffer

	// Mutable state tied to a concrete session.
	session *session

	// Mutable state tied to a particular vpn run.
	tunnel *tunnelInfo

	// Options are OpenVPN options that come from parsing a subset of the OpenVPN
	// configuration directives, plus some non-standard config directives.
	options *Options

	// eventListener is a channel to which Event_*- will be sent if
	// the channel is not nil.
	eventListener chan uint8

	failed bool
}

var _ vpnMuxer = &muxer{} // Ensure that we implement the vpnMuxer interface.

//
// Interfaces
//

// vpnMuxer contains all the behavior expected by the muxer.
type vpnMuxer interface {
	Handshake(ctx context.Context) error
	Reset(net.Conn, *session) error
	InitDataWithRemoteKey() error
	SetEventListener(chan uint8)
	Write([]byte) (int, error)
	Read([]byte) (int, error)
}

// controlHandler manages the control "channel".
type controlHandler interface {
	SendHardReset(net.Conn, *session) error
	ParseHardReset([]byte) (sessionID, error)
	SendACK(net.Conn, *session, packetID) error
	PushRequest() []byte
	ReadPushResponse([]byte) map[string][]string
	ControlMessage(*session, *Options) ([]byte, error)
	ReadControlMessage([]byte) (*keySource, string, error)
}

// dataHandler manages the data "channel".
type dataHandler interface {
	SetupKeys(*dataChannelKey) error
	SetPeerID(int) error
	WritePacket(net.Conn, []byte) (int, error)
	ReadPacket(*packet) ([]byte, error)
	DecodeEncryptedPayload([]byte, *dataChannelState) (*encryptedData, error)
	EncryptAndEncodePayload([]byte, *dataChannelState) ([]byte, error)
}

//
// muxer initialization
//

// muxFactory acepts a net.Conn, a pointer to an Options object, and another
// pointer to a tunnelInfo object, and returns a vpnMuxer and an error if it
// could not be initialized. This type is used to be able to mock a muxer while
// testing the Client.
type muxFactory func(conn net.Conn, options *Options, tunnel *tunnelInfo) (vpnMuxer, error)

// newMuxerFromOptions returns a configured muxer, and any error if the
// operation could not be completed.
func newMuxerFromOptions(conn net.Conn, options *Options, tunnel *tunnelInfo) (vpnMuxer, error) {
	control := &control{}
	session, err := newSession()
	if err != nil {
		return &muxer{}, err
	}
	data, err := newDataFromOptions(options, session)
	if err != nil {
		return &muxer{}, err
	}
	br := bytes.NewBuffer(nil)

	m := &muxer{
		conn:      conn,
		session:   session,
		options:   options,
		control:   control,
		data:      data,
		tunnel:    tunnel,
		bufReader: br,
	}
	return m, nil
}

//
// observability
//

// SetEvenSetEventListener assigns the passed channel as the event listener for
// this muxer.
func (m *muxer) SetEventListener(el chan uint8) {
	m.eventListener = el
}

// emit sends the passed stage into any configured EventListener
func (m *muxer) emit(stage uint8) {
	select {
	case m.eventListener <- stage:
	default:
		// do not deliver
	}
}

//
// muxer handshake
//

// Handshake performs the OpenVPN "handshake" operations serially. Accepts a
// Context, and itt returns any error that is raised at any of the underlying
// steps.
func (m *muxer) Handshake(ctx context.Context) (err error) {
	errch := make(chan error, 1)
	go func() {
		errch <- m.handshake()
	}()
	select {
	case err = <-errch:
	case <-ctx.Done():
		err = ctx.Err()
	}
	return
}

func (m *muxer) handshake() error {
	// 1. control channel sends reset, parse response.

	m.emit(EventReset)

	if err := m.Reset(m.conn, m.session); err != nil {
		return fmt.Errorf("%w: %s", ErrBadHandshake, err)

	}

	// 2. TLS handshake.

	// TODO(ainghazal): move the initialization step to an early phase and keep a ref in the muxer
	if !m.options.hasAuthInfo() {
		return fmt.Errorf("%w: %s", errBadInput, "expected certificate or username/password")
	}
	certCfg, err := newCertConfigFromOptions(m.options)
	if err != nil {
		return err
	}

	tlsConf, err := initTLSFn(m.session, certCfg)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrBadTLSHandshake, err)

	}
	tlsConn, err := newControlChannelTLSConn(m.conn, m.session)
	m.emit(EventTLSConn)

	if err != nil {
		return fmt.Errorf("%w: %s", ErrBadTLSHandshake, err)
	}

	m.emit(EventTLSHandshake)

	tls, err := tlsHandshakeFn(tlsConn, tlsConf)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrBadTLSHandshake, err)

	}

	m.emit(EventTLSHandshakeDone)

	m.tls = tls
	logger.Info("TLS handshake done")

	// 3. data channel init (auth, push, data initialization).

	if err := m.InitDataWithRemoteKey(); err != nil {
		return fmt.Errorf("%w: %s", ErrBadDataHandshake, err)

	}

	m.emit(EventDataInitDone)

	logger.Info("VPN handshake done")
	return nil
}

// Reset sends a hard-reset packet to the server, and awaits the server
// confirmation.
func (m *muxer) Reset(conn net.Conn, s *session) error {
	if m.control == nil {
		return fmt.Errorf("%w:%s", errBadInput, "bad control")
	}
	if err := m.control.SendHardReset(conn, s); err != nil {
		return err
	}

	resp, err := readPacket(m.conn)
	if err != nil {
		return err
	}

	remoteSessionID, err := m.control.ParseHardReset(resp)

	// here we could check if we have received a remote session id but
	// our session.remoteSessionID is != from all zeros
	if err != nil {
		return err
	}
	m.session.RemoteSessionID = remoteSessionID

	logger.Infof("Remote session ID: %x", m.session.RemoteSessionID)
	logger.Infof("Local session ID:  %x", m.session.LocalSessionID)

	// we assume id is 0, this is the first packet we ack.
	// XXX I could parse the real packet id from server instead. this
	// _might_ be important when re-keying?
	return m.control.SendACK(m.conn, m.session, packetID(1))
}

//
// muxer: read and handle packets
//

// handleIncoming packet reads the next packet available in the underlying
// socket. It returns true if the packet was a data packet; otherwise it will
// process it but return false.
func (m *muxer) handleIncomingPacket(data []byte) (bool, error) {
	if m.data == nil {
		logger.Errorf("uninitialized muxer")
		return false, errBadInput
	}
	var input []byte
	if data == nil {
		parsed, err := readPacket(m.conn)
		if err != nil {
			return false, err
		}
		input = parsed
	} else {
		input = data
	}

	if isPing(input) {
		err := handleDataPing(m.conn, m.data)
		if err != nil {
			logger.Errorf("cannot handle ping: %s", err.Error())
		}
		return false, nil
	}

	p, err := parsePacketFromBytes(input)
	if err != nil {
		logger.Error(err.Error())
		return false, err
	}
	if p.isACK() {
		logger.Warn("muxer: got ACK (ignored)")
		return false, err
	}
	if p.isControl() {
		logger.Infof("Got control packet: %d", len(data))
		// Here the server might be requesting us to reset, or to
		// re-key (but I keep ignoring that case for now).
		// we're doing nothing for now.
		fmt.Println(hex.Dump(p.payload))
		return false, err
	}
	if !p.isData() {
		logger.Warnf("unhandled data. (op: %d)", p.opcode)
		fmt.Println(hex.Dump(data))
		return false, err
	}

	// at this point, the incoming packet should be
	// a data packet that needs to be processed
	// (decompress+decrypt)

	plaintext, err := m.data.ReadPacket(p)
	if err != nil {
		logger.Errorf("bad decryption: %s", err.Error())
		// XXX I'm not sure returning false is the right thing to do here.
		return false, err
	}

	// all good! we write the plaintext into the read buffer.
	// the caller is responsible for reading from there.
	m.bufReader.Write(plaintext)
	return true, nil
}

// handleDataPing replies to an openvpn-ping with a canned response.
func handleDataPing(conn net.Conn, data dataHandler) error {
	log.Println("openvpn-ping, sending reply")
	_, err := data.WritePacket(conn, pingPayload)
	return err
}

// readTLSPacket reads a packet over the TLS connection.
func (m *muxer) readTLSPacket() ([]byte, error) {
	data := make([]byte, 4096)
	_, err := m.tls.Read(data)
	return data, err
}

// readAndLoadRemoteKey reads one incoming TLS packet, and tries to parse the
// response contained in it. If the server response is the right kind of
// packet, it will store the remote key and the parts of the remote options
// that will be of use later.
func (m *muxer) readAndLoadRemoteKey() error {
	//TODO: mega-kostyl
	m.session.lastACK++
	data, err := m.readTLSPacket()
	if err != nil {
		return err
	}
	if !isControlMessage(data) {
		return fmt.Errorf("%w: %s", errBadControlMessage, "expected null header")
	}

	// Parse the received data: we expect remote key and remote options.
	remoteKey, remoteOptStr, err := m.control.ReadControlMessage(data)
	if err != nil {
		logger.Errorf("cannot parse control message")
		return fmt.Errorf("%w: %s", ErrBadHandshake, err)
	}

	// Store the remote key.
	key, err := m.session.ActiveKey()
	if err != nil {
		logger.Errorf("cannot get active key")
		return fmt.Errorf("%w: %s", ErrBadHandshake, err)
	}
	err = key.addRemoteKey(remoteKey)
	if err != nil {
		logger.Errorf("cannot add remote key")
		return fmt.Errorf("%w: %s", ErrBadHandshake, err)
	}

	// Parse and update the useful fields from the remote options (mtu).
	ti := newTunnelInfoFromRemoteOptionsString(remoteOptStr)
	m.tunnel.mtu = ti.mtu
	return nil
}

// sendPushRequest sends a push request over the TLS channel.
func (m *muxer) sendPushRequest() (int, error) {
	return m.tls.Write(m.control.PushRequest())
}

// readPushReply reads one incoming TLS packet, where we expect to find the
// response to our push request. If the server response is the right kind of
// packet, it will store the parts of the pushed options that will be of use
// later.
func (m *muxer) readPushReply() error {
	if m.control == nil || m.tunnel == nil {
		return fmt.Errorf("%w:%s", errBadInput, "muxer badly initialized")

	}
	resp, err := m.readTLSPacket()
	if err != nil {
		return err
	}

	logger.Info("Server pushed options")

	if isBadAuthReply(resp) {
		return errBadAuth
	}

	if !isPushReply(resp) {
		return fmt.Errorf("%w:%s", errBadServerReply, "expected push reply")
	}

	optsMap := m.control.ReadPushResponse(resp)
	ti := newTunnelInfoFromPushedOptions(optsMap)

	m.tunnel.ip = ti.ip
	m.tunnel.gw = ti.gw
	m.tunnel.peerID = ti.peerID

	logger.Infof("Tunnel IP: %s", m.tunnel.ip)
	logger.Infof("Gateway IP: %s", m.tunnel.gw)
	logger.Infof("Peer ID: %d", m.tunnel.peerID)

	return nil
}

// sendControl message sends a control message over the TLS channel.
func (m *muxer) sendControlMessage() error {
	cm, err := m.control.ControlMessage(m.session, m.options)
	if err != nil {
		return err
	}
	if _, err := m.tls.Write(cm); err != nil {
		return err
	}
	return nil
}

// InitDataWithRemoteKey initializes the internal data channel. To do that, it sends a
// control packet, parses the response, and derives the cryptographic material
// that will be used to encrypt and decrypt data through the tunnel. At the end
// of this exchange, the data channel is ready to be used.
func (m *muxer) InitDataWithRemoteKey() error {

	// 1. first we send a control message.

	if err := m.sendControlMessage(); err != nil {
		return err
	}

	// 2. then we read the server response and load the remote key.

	if err := m.readAndLoadRemoteKey(); err != nil {
		return err
	}

	// 3. now we can initialize the data channel.

	key0, err := m.session.ActiveKey()
	if err != nil {
		return err
	}

	err = m.data.SetupKeys(key0)
	if err != nil {
		return err
	}

	// 4. finally, we ask the server to push remote options to us. we parse
	// them and keep some useful info.

	if _, err := m.sendPushRequest(); err != nil {
		return err
	}
	if err := m.readPushReply(); err != nil {
		return err
	}

	err = m.data.SetPeerID(m.tunnel.peerID)
	if err != nil {
		return err
	}

	return nil
}

// Write sends user bytes as encrypted packets in the data channel. It returns
// the number of written bytes, and an error if the operation could not succeed.
func (m *muxer) Write(b []byte) (int, error) {
	if m.data == nil {
		return 0, fmt.Errorf("%w:%s", errBadInput, "data not initialized")

	}
	return m.data.WritePacket(m.conn, b)
}

// Read reads bytes after decrypting packets from the data channel. This is the
// user-view of the VPN connection reads. It returns the number of bytes read,
// and an error if the operation could not succeed.
func (m *muxer) Read(b []byte) (int, error) {
	for {
		ok, err := m.handleIncomingPacket(nil)
		if err != nil {
			return 0, err
		}
		if ok {
			break
		}
	}
	return m.bufReader.Read(b)
}
