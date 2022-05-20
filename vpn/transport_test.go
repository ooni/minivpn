package vpn

import (
	"errors"
	"net"
	"reflect"
	"testing"

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
