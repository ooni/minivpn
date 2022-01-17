package vpn

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"log"
	"net"
	"time"
)

func genRandomBytes(size int) (b []byte, err error) {
	b = make([]byte, size)
	_, err = rand.Read(b)
	if err != nil {
		return b, err
	}
	return b, err
}

// XXX the idea with this wrapper is to have the TLS Handshake sending its Client HELLO
// payload as part of one openvpn CONTROL_V1 packet

type controlWrapper struct {
	control *controlCh
}

func (cw controlWrapper) Write(b []byte) (n int, err error) {
	return cw.control.sendControlV1(b)
}

func (cw controlWrapper) Read(b []byte) (int, error) {
	return cw.control.conn.Read(b)
}

func (cw controlWrapper) LocalAddr() net.Addr {
	return cw.control.conn.LocalAddr()
}

func (cw controlWrapper) RemoteAddr() net.Addr {
	return cw.control.conn.RemoteAddr()
}

func (cw controlWrapper) SetDeadline(t time.Time) error {
	return cw.control.conn.SetDeadline(t)
}

func (cw controlWrapper) SetReadDeadline(t time.Time) error {
	return cw.control.conn.SetReadDeadline(t)
}

func (cw controlWrapper) SetWriteDeadline(t time.Time) error {
	return cw.control.conn.SetWriteDeadline(t)
}

func (cw controlWrapper) Close() error {
	return cw.control.conn.Close()
}

// control_channel.go --------------------
type controlCh struct {
	RemoteID  []byte
	SessionID []byte
	localPID  uint32
	tls       net.Conn // do not use, replace
	conn      net.Conn
}

func (c *controlCh) initSession() error {
	b, err := genRandomBytes(8)
	if err != nil {
		return err
	}
	c.SessionID = b
	log.Printf("Local session ID: %x\n", string(c.SessionID))
	return nil
}

func (c *controlCh) sendHardReset() {
	log.Printf("Sending HARD_RESET %08x ...\n", c.localPID)
	c.sendControl(P_CONTROL_HARD_RESET_CLIENT_V2, 0, []byte(""))
}

func (c *controlCh) readHardReset(d []byte) int {
	log.Printf(">>> got data: %08x\n", d)
	if d[0] != 0x40 {
		log.Fatal("Not a hard reset response packet")
	}
	if len(c.RemoteID) != 0 {
		if !areBytesEqual(c.RemoteID[:], d[1:9]) {
			log.Printf("Offending session id: %08x\n", d[1:9])
			log.Fatal("Invalid remote session ID!")
		}
	} else {
		c.RemoteID = d[1:9]
		log.Printf("Learned Remote Session id: %x\n", c.RemoteID)
	}
	log.Println("len(ack)", d[9]) // zero-length ack for now, need to parse 10:... if sthing
	return 0
}

func (c *controlCh) sendControlV1(data []byte) (n int, err error) {
	log.Printf("Sending CONTROL_V1 %08x (with %d bytes)...",
		c.localPID, len(data))
	return c.sendControl(P_CONTROL_V1, 0, data)
}

func (c *controlCh) sendControl(opcode int, ack int, payload []byte) (n int, err error) {
	p := make([]byte, 1)
	p[0] = byte(opcode << 3)
	p = append(p, c.SessionID...)
	// XXX if ack...
	pid := make([]byte, 4)
	binary.BigEndian.PutUint32(pid, c.localPID)
	p = append(p, pid...)
	c.localPID += 1
	if len(payload) != 0 {
		p = append(p, payload...)
	}
	log.Printf("%08x\n", p)
	return c.conn.Write(p)
}

func (c *controlCh) initTLS() {
	log.Println("Initializing TLS context...")
	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS12,
		//ServerName: "1.1.1.1",
		InsecureSkipVerify: true,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		},
	}
	udp := controlWrapper{c}
	tlsConn := tls.Client(udp, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		log.Fatal(err)
	}
	c.tls = net.Conn(tlsConn)
}

// --------------------------------------
// data_channel.go
type dataCh struct{}

// --------------------------------------

type Client struct {
	Host    string
	Port    string
	Proto   string
	running bool
	initSt  int
	con     net.Conn
	ctrl    *controlCh
	data    *dataCh
}

func (c *Client) Run() {
	// -------------------------------------------------------------
	// Phase 1: stablishing contact
	log.Printf("Connecting to %s:%s UDP...\n", c.Host, c.Port)
	// 1. open DGRAM socket
	conn, err := net.Dial(c.Proto, c.Host+":"+c.Port)
	checkError(err)
	c.con = conn
	// 2. init controlChannel
	c.ctrl = &controlCh{conn: conn}
	log.Println("Control Channel created")
	c.ctrl.initSession()
	// 3. init dataChannel
	c.data = &dataCh{}
	// 4. hard reset (waits for ack, get id)
	c.ctrl.sendHardReset()
	// ------------------------------------------------------------
	// XXX hardcoding 0 for now
	id := c.ctrl.readHardReset(c.recv(0))
	c.sendAck(uint32(id))
	// -------------------------------------------------------------
	// 5. init TLS
	c.ctrl.initTLS()
	// 6. socket noblock, needed in Go?
	// 7. sending HELLO
	// log.Println("Sending hello...")
	// ??. handshake don
	//log.Println("Handshake finished!")
	// state = ST_CONTROL_CHANNEL_OPEN
	c.running = true
	c.initSt = ST_CONTROL_CHANNEL_OPEN
	// select instead?
	/*
		while (c.running) {
		    // check initSt etc
		    c.ctrl.sendControlMessage()
		    c.ctrl.sendPushRequest()
		    c.data.setup()
		    // how to do this, just fp?
		    c.callback()
		}
	*/
}

func (c *Client) sendAck(ackPid uint32) {
	log.Printf("ACK'ing packet %08x...", ackPid)
	if len(c.ctrl.RemoteID) == 0 {
		log.Fatal("Remote session should not be null!")
	}
	p := make([]byte, 1)
	p[0] = 0x28 // P_ACK_V1 0x05 (5b) + 0x0 (3b)
	p = append(p, c.ctrl.SessionID...)
	p = append(p, 0x01)
	ack := make([]byte, 4)
	binary.BigEndian.PutUint32(ack, ackPid)
	p = append(p, ack...)
	p = append(p, c.ctrl.RemoteID...)
	c.con.Write(p)
}

func (c *Client) handleIncoming() {
	data := c.recv(4096)
	op := data[0] >> 3
	if op == byte(P_ACK_V1) {
		log.Println("Received ACK")
	}
}

func (c *Client) recv(size int) []byte {
	if size == 0 {
		size = 8192
	}
	var recvData = make([]byte, size)
	var numBytes, _ = c.con.Read(recvData)
	return recvData[:numBytes]
}

func (c *Client) stop() {
	c.running = false
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func areBytesEqual(s1, s2 []byte) bool {
	return 0 == bytes.Compare(s1, s2)
}
