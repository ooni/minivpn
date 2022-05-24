package vpn

import (
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/ainghazal/minivpn/vpn/mocks"
)

func makeTestinConnFromNetwork(network string) net.Conn {
	mockAddr := &mocks.Addr{}
	mockAddr.MockNetwork = func() string {
		return network
	}
	c := &mocks.Conn{}
	c.MockLocalAddr = func() net.Addr {
		return mockAddr
	}
	switch network {
	case "udp":
		c.MockRead = func(b []byte) (int, error) {
			out := []byte("alles ist gut")
			copy(b, out)
			return len(out), nil
		}
	case "tcp":
		c.MockRead = func(b []byte) (int, error) {
			var out []byte
			switch c.Count {
			case 0:
				out = []byte{0x00, 0x0d}
				copy(b, out)
				c.Count += 1
			case 1:
				out = []byte("alles ist gut")
				copy(b, out)
			}
			return len(out), nil
		}
	}
	return c
}

func Test_readPacket(t *testing.T) {

	type args struct {
		conn net.Conn
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr error
	}{
		{
			name: "test read from udp conn is ok",
			args: args{
				conn: makeTestinConnFromNetwork("udp"),
			},
			want:    []byte("alles ist gut"),
			wantErr: nil,
		},
		{
			name: "test read from tcp conn is ok",
			args: args{
				conn: makeTestinConnFromNetwork("tcp"),
			},
			want:    []byte("alles ist gut"),
			wantErr: nil,
		},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readPacket(tt.args.conn)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("readPacket() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("readPacket() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_NewTLSConn(t *testing.T) {
	conn := makeTestinConnFromNetwork("udp")
	s := makeTestingSession()
	_, err := NewTLSConn(conn, s)
	if err != nil {
		t.Errorf("NewTLSConn() error = %v, want = nil", err)
	}
}

type MockTLSConn struct {
	mocks.Conn
	closedCalled           bool
	localAddrCalled        bool
	remoteAddrCalled       bool
	setDeadlineCalled      bool
	setReadDeadlineCalled  bool
	setWriteDeadlineCalled bool
}

func makeConnForTransportTest() *MockTLSConn {
	localAddr := &mocks.Addr{}
	localAddr.MockString = func() string { return "1.1.1.1" }
	localAddr.MockNetwork = func() string { return "udp" }

	remoteAddr := &mocks.Addr{}
	remoteAddr.MockString = func() string { return "2.2.2.2" }
	remoteAddr.MockNetwork = func() string { return "udp" }

	c := &MockTLSConn{}
	c.MockClose = func() error {
		c.closedCalled = true
		return nil
	}
	c.MockLocalAddr = func() net.Addr {
		c.localAddrCalled = true
		return localAddr
	}
	c.MockRemoteAddr = func() net.Addr {
		c.remoteAddrCalled = true
		return remoteAddr
	}
	c.MockSetDeadline = func(time.Time) error {
		c.setDeadlineCalled = true
		return nil
	}
	c.MockSetReadDeadline = func(time.Time) error {
		c.setReadDeadlineCalled = true
		return nil
	}
	c.MockSetWriteDeadline = func(time.Time) error {
		c.setWriteDeadlineCalled = true
		return nil
	}
	return c
}

func makeTLSConn() (*TLSConn, *MockTLSConn) {
	c := makeConnForTransportTest()
	t := &TLSConn{}
	t.conn = c
	return t, c
}

func Test_TLSConn_Close(t *testing.T) {
	tc, conn := makeTLSConn()
	err := tc.Close()
	if err != nil {
		t.Errorf("TLSConn.Close() error = %v, want = nil", err)
	}
	if !conn.closedCalled {
		t.Error("TLSConn.Close(): conn.Close() not called")
	}
}

func Test_TLSConn_LocalAddr(t *testing.T) {
	tc, conn := makeTLSConn()
	want := "1.1.1.1"
	if addr := tc.LocalAddr(); addr.String() != want {
		t.Errorf("TLSConn.LocalAddr() got = %s, want = %s", addr, want)
	}
	if !conn.localAddrCalled {
		t.Error("TLSConn.LocalAddr(): conn.LocalAddr() not called")
	}
}

func Test_TLSConn_RemoteAddr(t *testing.T) {
	tc, conn := makeTLSConn()
	want := "2.2.2.2"
	if addr := tc.RemoteAddr(); addr.String() != want {
		t.Errorf("TLSConn.RemoteAddr() got = %s, want = %s", addr, want)
	}
	if !conn.remoteAddrCalled {
		t.Error("TLSConn.RemoteAddr(): conn.RemoteAddr() not called")
	}
}

func Test_TLSConn_SetDeadline(t *testing.T) {
	tc, conn := makeTLSConn()
	err := tc.SetDeadline(time.Now().Add(time.Second))
	if err != nil {
		t.Errorf("TLSConn.SetDeadline() error = %v, want = nil", err)
	}
	if !conn.setDeadlineCalled {
		t.Error("TLSConn.SetDeadline(): conn.SetDeadline() not called")
	}
}

func Test_TLSConn_SetReadDeadline(t *testing.T) {
	tc, conn := makeTLSConn()
	err := tc.SetReadDeadline(time.Now().Add(time.Second))
	if err != nil {
		t.Errorf("TLSConn.SetReadDeadline() error = %v, want = nil", err)
	}
	if !conn.setReadDeadlineCalled {
		t.Error("TLSConn.SetReadDeadline(): conn.SetReadDeadline() not called")
	}
}

func Test_TLSConn_SetWriteDeadline(t *testing.T) {
	tc, conn := makeTLSConn()
	err := tc.SetWriteDeadline(time.Now().Add(time.Second))
	if err != nil {
		t.Errorf("TLSConn.SetWriteDeadline() error = %v, want = nil", err)
	}
	if !conn.setWriteDeadlineCalled {
		t.Error("TLSConn.SetWriteDeadline(): conn.SetWriteDeadline() not called")
	}
}
