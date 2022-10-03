package vpn

import (
	"bytes"
	"context"
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/ooni/minivpn/vpn/mocks"
	tls "github.com/refraction-networking/utls"
)

func Test_newMuxerFromOptions(t *testing.T) {
	randomFn = func(int) ([]byte, error) {
		return []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, nil
	}
	ts, _ := newSession()
	testReliable := newReliableTransport(ts)

	type args struct {
		conn    net.Conn
		options *Options
		tunnel  *tunnelInfo
	}
	tests := []struct {
		name    string
		args    args
		want    *muxer
		wantErr error
	}{
		{
			name: "get muxer ok",
			args: args{
				conn:    makeTestingConnForWrite("udp", "10.0.42.2", 42),
				options: makeTestingOptions(t, "AES-128-GCM", "sha1"),
				tunnel:  &tunnelInfo{},
			},
			want: &muxer{
				conn:     makeTestingConnForWrite("udp", "10.0.42.2", 42),
				control:  &control{},
				reliable: testReliable,
				options:  makeTestingOptions(t, "AES-128-GCM", "sha1"),
			},
			wantErr: nil,
		},
		// TODO: Add more test cases:
		// failure in newData()
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newMuxerFromOptions(tt.args.conn, tt.args.options, tt.args.tunnel)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("newMuxerFromOptions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// TODO(ainghazal): we cannot compare the options because the paths for the certs are going to be different
			// I think this calls from separating the initial options from a more structured config
			// with the parsed, loaded certs instead.
		})
	}
}

func makeTestingConnForHandshake(network, addr string, n int) net.Conn {
	ma := &mocks.Addr{}
	ma.MockString = func() string {
		return addr
	}
	ma.MockNetwork = func() string {
		return network
	}

	c := &mocks.Conn{}
	c.MockLocalAddr = func() net.Addr {
		return ma
	}
	c.MockWrite = func([]byte) (int, error) {
		return n, nil
	}
	c.MockRead = func(b []byte) (int, error) {
		switch c.Count {
		case 0:
			// this is the expected reset response from server
			rp := []byte{
				0x40,
				0x00, 0x01, 0x02, 0x03, 0x04,
				0x05, 0x06, 0x07, 0x08,
			}
			copy(b[:], rp)
			c.Count += 1
			return len(rp), nil
		case 1:
			// control message data (to load remote key)
			p := []byte{0x00, 0x00, 0x00, 0x00, 0x02}
			p = append(p, bytes.Repeat([]byte{0x01}, 70)...)
			copy(b[:], p)
			c.Count += 1
			return len(p), nil
		case 2:
			// control message data (to load remote key)
			p := []byte("PUSH_REPLY")
			copy(b[:], p)
			c.Count += 1
			return len(p), nil
		}

		return 0, nil
	}
	c.MockClose = func() error {
		return nil
	}
	return c
}

type mockMuxerForHandshake struct {
	muxer
}

func (md *mockMuxerForHandshake) sendControlMessage() error {
	return nil
}

func (md *mockMuxerForHandshake) readAndLoadRemoteKey() error {
	return nil
}

type mockMuxerWithDummyHandshake struct {
	mockMuxerForHandshake
}

func (md *mockMuxerWithDummyHandshake) Handshake(context.Context) error {
	return nil
}

func Test_muxer_Handshake(t *testing.T) {
	makeData := func() *data {
		options := makeTestingOptions(t, "AES-128-GCM", "sha1")
		data, _ := newDataFromOptions(options, makeTestingSession())
		return data
	}

	m := &mockMuxerForHandshake{}
	m.control = &control{}
	m.data = makeData()
	m.tunnel = &tunnelInfo{}
	s, err := newSession()
	if err != nil {
		t.Error("session failed, cannot run handshake test")
	}
	m.reliable = newReliableTransport(s)
	m.options = makeTestingOptions(t, "AES-128-GCM", "sha512")
	m.tls = makeTestingConnForWrite("udp", "0.0.0.0", 42)
	m.conn = makeTestingConnForHandshake("udp", "10.0.0.0", 42)

	origInit := initTLSFn
	origHandshake := tlsHandshakeFn

	defer func() {
		initTLSFn = origInit
		tlsHandshakeFn = origHandshake
	}()

	// monkey patch the global functions

	initTLSFn = func(*session, *certConfig) (*tls.Config, error) {
		return &tls.Config{InsecureSkipVerify: true}, nil
	}
	tlsHandshakeFn = func(tc *controlChannelTLSConn, tconf *tls.Config) (net.Conn, error) {
		return m.conn, nil
	}

	// and now for the test itself...

	//err = m.Handshake(context.Background())
	//if err != nil {
	//	t.Errorf("muxer.Handshake() error = %v, wantErr nil", err)
	//	return
	//}
}

func makePacketForHandleIncomingTest(opcode byte, s *session) *packet {
	p := &packet{
		id:              packetID(1), // always a good packet for a clean session
		opcode:          opcode,
		keyID:           0x00,
		payload:         []byte("aaa"),
		localSessionID:  s.LocalSessionID,
		remoteSessionID: s.RemoteSessionID,
		acks:            []packetID{},
	}
	return p
}

//I have modified muxer.handleIncomingPacket() so that it optionally receives a []byte
//in order to make it easier to test payloads. here we go:
type mockDataHandler struct{}

func (m *mockDataHandler) SetupKeys(*dataChannelKey) error {
	return nil
}

func (m *mockDataHandler) WritePacket(net.Conn, []byte) (int, error) {
	return 42, nil
}

func (m *mockDataHandler) ReadPacket(*packet) ([]byte, error) {
	return []byte("alles ist gut"), nil
}

func (m *mockDataHandler) DecodeEncryptedPayload([]byte, *dataChannelState) (*encryptedData, error) {
	return &encryptedData{}, nil
}

func (m *mockDataHandler) EncryptAndEncodePayload([]byte, *dataChannelState) ([]byte, error) {
	return []byte("this is not a payload"), nil
}

func (m *mockDataHandler) SetPeerID(int) error {
	return nil
}

type mockDataHandlerBadReadPacket struct {
	mockDataHandler
}

func (m *mockDataHandlerBadReadPacket) ReadPacket(*packet) ([]byte, error) {
	dummy := errors.New("dummy error")
	return []byte{}, dummy
}

var _ dataHandler = &mockData{}

func Test_muxer_handleIncomingPacket(t *testing.T) {
	/*
	 options := makeTestingOptions(t, "AES-128-GCM", "sha1")
	 data, _ := newDataFromOptions(options, makeTestingSession())
	 m := muxer{
	 	conn:      makeTestingConnForWrite("udp", "10.0.0.1", 42),
	 	data:      data,
	 	bufReader: &bytes.Buffer{},
	 	reliable:  newReliableTransport(makeTestingSession()),
	 }
	*/
	makeData := func() *data {
		options := makeTestingOptions(t, "AES-128-GCM", "sha1")
		data, _ := newDataFromOptions(options, makeTestingSession())
		return data
	}
	m := &mockMuxerForHandshake{}
	m.control = &control{}
	m.data = makeData()
	m.tunnel = &tunnelInfo{}
	s, err := newSession()
	if err != nil {
		t.Error("session failed, cannot run handshake test")
	}
	m.reliable = newReliableTransport(s)
	m.options = makeTestingOptions(t, "AES-128-GCM", "sha512")
	m.tls = makeTestingConnForWrite("udp", "0.0.0.0", 42)
	m.conn = makeTestingConnForHandshake("udp", "10.0.0.0", 42)

	// ping data
	if ok, _ := m.handleIncomingPacket(pingPayload); ok {
		t.Errorf("muxer.handleIncomingPacket(): expected !ok with ping payload")
		return
	}
	// packets with different opcodes
	if ok, _ := m.handleIncomingPacket([]byte{}); ok {
		t.Errorf("muxer.handleIncomingPacket(): expected !ok with empty bytes")
		return
	}
	p := &packet{opcode: pACKV1}
	if ok, _ := m.handleIncomingPacket(p.Bytes()); ok {
		t.Errorf("muxer.handleIncomingPacket(): expected !ok with ack packet")
		return
	}
	p = &packet{opcode: pControlV1}
	if ok, _ := m.handleIncomingPacket(p.Bytes()); ok {
		t.Errorf("muxer.handleIncomingPacket(): expected !ok with control packet")
		return
	}
	p = &packet{opcode: pControlV1}
	if ok, _ := m.handleIncomingPacket(p.Bytes()); ok {
		t.Errorf("muxer.handleIncomingPacket(): expected !ok with control packet")
		return
	}
	p = &packet{opcode: byte(0xff)}
	if ok, _ := m.handleIncomingPacket(p.Bytes()); ok {
		t.Errorf("muxer.handleIncomingPacket(): expected !ok with unknown opcode")
		return
	}
	p = &packet{opcode: pDataV1, payload: []byte("aaa")}
	if _, err := m.handleIncomingPacket(p.Bytes()); !errors.Is(err, errCannotDecrypt) {
		t.Errorf("muxer.handleIncomingPacket(): expected description error with data opcode")
		return
	}

	// replace dataHandler in muxer with a method that raises error on ReadPacket()
	/*
	 t.Run("error in ReadPacket() should propagate", func(t *testing.T) {
	 	m = muxer{
	 		data:      &mockDataHandlerBadReadPacket{},
	 		bufReader: &bytes.Buffer{},
	 	}
	 	p = &packet{opcode: pDataV1}
	 	if ok, _ := m.handleIncomingPacket(p.Bytes()); ok {
	 		t.Errorf("muxer.handleIncomingPacket(): expected !ok with error in ReadPacket()")
	 	}
	 })
	*/
}

func Test_muxer_Write(t *testing.T) {

	makeData := func() *data {
		options := makeTestingOptions(t, "AES-128-GCM", "sha1")
		data, _ := newDataFromOptions(options, makeTestingSession())
		return data
	}

	type fields struct {
		conn net.Conn
		data dataHandler
	}
	type args struct {
		b []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    int
		wantErr error
	}{
		{
			name: "write calls data.WritePacket",
			fields: fields{
				conn: makeTestingConnForWrite("udp", "10.0.1.1", 42),
				data: makeData(),
			},
			args:    args{[]byte("alles ist gut")},
			want:    42,
			wantErr: nil,
		},

		// TODO can add more tests:
		// [ ] check that the error raised by the underlying data read is the error we
		// expect to be returned.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &muxer{
				conn: tt.fields.conn,
				data: tt.fields.data,
			}
			got, err := m.Write(tt.args.b)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("muxer.Write() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("muxer.Write() = %v, want %v", got, tt.want)
			}
		})
	}
}

func makeTestingConnForRead(retInt int, retErr error, payload []byte) net.Conn {
	ma := &mocks.Addr{}
	ma.MockString = func() string {
		return "10.0.42.2"
	}
	ma.MockNetwork = func() string {
		return "udp"
	}

	mc := &mocks.Conn{}
	mc.MockLocalAddr = func() net.Addr {
		return ma
	}
	mc.MockRead = func(b []byte) (int, error) {
		copy(b[:], payload)
		return retInt, retErr
	}
	return mc
}

type mockData struct {
	data
}

func (md *mockData) ReadPacket(*packet) ([]byte, error) {
	return []byte("alles ist gut"), nil
}

func Test_muxer_Read(t *testing.T) {
	// XXX(ainghazal): I'm not sure this is a very good test.
	// what I want to test:
	// - that I call readPacket(mockConn) - I'm assuming we get a good data packet
	// - that I call data.ReadPacket(p)
	// - that we get the right return from muxer.Read()
	// - that the expected buffer is written into the buffer that we pass to Read()

	testDataPacket := &packet{opcode: pDataV1, payload: []byte("discarded")}
	bufData := "alles ist gut"

	b := make([]byte, 4096)
	want := len(bufData)
	m := &muxer{
		conn:      makeTestingConnForRead(want, nil, testDataPacket.Bytes()),
		data:      &mockData{},
		bufReader: bytes.NewBuffer(nil),
	}
	got, err := m.Read(b)
	if err != nil {
		t.Errorf("muxer.Read() error = %v, wantErr nil", err)
		return
	}
	if got != want {
		t.Errorf("muxer.Read() = %v, want %v", got, want)
	}
	if !bytes.Equal(b[:len(bufData)], []byte(bufData)) {
		t.Errorf("muxer.Read() = %v, want %v", string(b[:len(bufData)]), string(bufData))
	}
}

func Test_muxer_readTLSPacket(t *testing.T) {
	type fields struct {
		conn      net.Conn
		tls       net.Conn
		control   controlHandler
		data      dataHandler
		bufReader *bytes.Buffer
		reliable  *reliableTransport
		tunnel    *tunnelInfo
		options   *Options
	}
	tests := []struct {
		name    string
		fields  fields
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &muxer{
				conn:      tt.fields.conn,
				tls:       tt.fields.tls,
				control:   tt.fields.control,
				data:      tt.fields.data,
				bufReader: tt.fields.bufReader,
				reliable:  tt.fields.reliable,
				tunnel:    tt.fields.tunnel,
				options:   tt.fields.options,
			}
			got, err := m.readTLSPacket()
			if (err != nil) != tt.wantErr {
				t.Errorf("muxer.readTLSPacket() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("muxer.readTLSPacket() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_muxer_readAndLoadRemoteKey(t *testing.T) {
	type fields struct {
		conn      net.Conn
		tls       net.Conn
		control   controlHandler
		data      dataHandler
		bufReader *bytes.Buffer
		reliable  *reliableTransport
		tunnel    *tunnelInfo
		options   *Options
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &muxer{
				conn:      tt.fields.conn,
				tls:       tt.fields.tls,
				control:   tt.fields.control,
				data:      tt.fields.data,
				bufReader: tt.fields.bufReader,
				reliable:  tt.fields.reliable,
				tunnel:    tt.fields.tunnel,
				options:   tt.fields.options,
			}
			if err := m.readAndLoadRemoteKey(); (err != nil) != tt.wantErr {
				t.Errorf("muxer.readAndLoadRemoteKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_muxer_readPushReply(t *testing.T) {
	type fields struct {
		conn      net.Conn
		tls       net.Conn
		control   controlHandler
		data      dataHandler
		bufReader *bytes.Buffer
		reliable  *reliableTransport
		tunnel    *tunnelInfo
		options   *Options
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr error
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &muxer{
				conn:      tt.fields.conn,
				tls:       tt.fields.tls,
				control:   tt.fields.control,
				data:      tt.fields.data,
				bufReader: tt.fields.bufReader,
				reliable:  tt.fields.reliable,
				tunnel:    tt.fields.tunnel,
				options:   tt.fields.options,
			}
			if err := m.readPushReply(); !errors.Is(err, tt.wantErr) {
				t.Errorf("muxer.readPushReply() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_muxer_emitSendsToListener(t *testing.T) {
	t.Run("emit writes event if listener not null", func(t *testing.T) {
		l := make(chan uint8, 2)
		m := &muxer{}
		m.SetEventListener(l)
		sent := uint8(2)
		m.emit(sent)
		got := <-l
		if got != sent {
			t.Errorf("expected %v, got %v", sent, got)
		}
	})
	t.Run("emit is a noop if evenlistener not set", func(t *testing.T) {
		m := &muxer{}
		sent := uint8(2)
		m.emit(sent)
	})
	t.Run("listener receives several events", func(t *testing.T) {
		l := make(chan uint8, 5)
		m := &muxer{}
		m.SetEventListener(l)
		received := []uint8{}
		sent := []uint8{1, 2, 3, 4, 5}
		for _, i := range sent {
			m.emit(i)
		}
		for _ = range sent {
			got := <-l
			received = append(received, got)
		}
		for i := range sent {
			if sent[i] != received[i] {
				t.Errorf("at [%d]: expected %v, got %v", i, sent, received)
				return
			}
		}
	})
}
