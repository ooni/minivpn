package vpn

import (
	"bytes"
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/ainghazal/minivpn/vpn/mocks"
)

func Test_newMuxerFromOptions(t *testing.T) {
	randomFn = func(int) ([]byte, error) {
		return []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, nil
	}
	testSession, _ := newSession()

	type args struct {
		conn    net.Conn
		options *Options
		tunnel  *tunnel
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
				options: makeTestingOptions("AES-128-GCM", "sha1"),
				tunnel:  &tunnel{},
			},
			want: &muxer{
				conn:    makeTestingConnForWrite("udp", "10.0.42.2", 42),
				control: &control{},
				session: testSession,
				options: makeTestingOptions("AES-128-GCM", "sha1"),
			},
			wantErr: nil,
		},
		// TODO: Add test cases
		// failure on newSession()
		// failure in newData()
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newMuxerFromOptions(tt.args.conn, tt.args.options, tt.args.tunnel)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("newMuxerFromOptions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Equal(got.session.RemoteSessionID[:], tt.want.session.RemoteSessionID[:]) {
				t.Errorf("newMuxerFromOptions() session = %v, want %v", got, tt.want)
			}
			if !bytes.Equal(got.session.LocalSessionID[:], tt.want.session.LocalSessionID[:]) {
				t.Errorf(
					"newMuxerFromOptions() session. = %v, want %v",
					got.session.LocalSessionID[:],
					tt.want.session.LocalSessionID[:],
				)
			}
			if !reflect.DeepEqual(got.options, tt.want.options) {
				t.Errorf("newMuxerFromOptions() options = %v, want %v", got.options, tt.want.options)
			}
		})
	}
}

func Test_muxer_Write(t *testing.T) {

	makeData := func() *data {
		options := makeTestingOptions("AES-128-GCM", "sha1")
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
			name: "write fails if data state is not initialized",
			fields: fields{
				conn: makeTestinConnFromNetwork("udp"),
				data: &data{},
			},
			args:    args{[]byte("alles ist bad")},
			want:    0,
			wantErr: errBadInput,
		},
		{
			name: "write fails if data state is nil",
			fields: fields{
				conn: makeTestinConnFromNetwork("udp"),
				data: nil,
			},
			args:    args{[]byte("alles ist bad")},
			want:    0,
			wantErr: errBadInput,
		},
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
		session   *session
		tunnel    *tunnel
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
				session:   tt.fields.session,
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
		session   *session
		tunnel    *tunnel
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
				session:   tt.fields.session,
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
		session   *session
		tunnel    *tunnel
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
				session:   tt.fields.session,
				tunnel:    tt.fields.tunnel,
				options:   tt.fields.options,
			}
			if err := m.readPushReply(); (err != nil) != tt.wantErr {
				t.Errorf("muxer.readPushReply() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
