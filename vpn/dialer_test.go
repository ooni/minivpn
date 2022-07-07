package vpn

import (
	"bytes"
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/ooni/minivpn/vpn/mocks"
	tls "github.com/refraction-networking/utls"
	"golang.zx2c4.com/go118/netip"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestNewTunDialer(t *testing.T) {
	type args struct {
		raw *RawDialer
	}
	tests := []struct {
		name string
		args args
		want TunDialer
	}{
		{
			name: "get dialer ok",
			args: args{
				raw: &RawDialer{},
			},
			want: TunDialer{
				raw: &RawDialer{},
				ns1: openDNSPrimary,
				ns2: openDNSSecondary,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewTunDialer(tt.args.raw); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewTunDialer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewTunDialerWithNameservers(t *testing.T) {
	type args struct {
		raw *RawDialer
		ns1 string
		ns2 string
	}
	tests := []struct {
		name string
		args args
		want TunDialer
	}{
		{
			name: "get tundialer with passed nameservers",
			args: args{
				raw: &RawDialer{},
				ns1: "8.8.8.8",
				ns2: "8.8.4.4",
			},
			want: TunDialer{
				raw: &RawDialer{},
				ns1: "8.8.8.8",
				ns2: "8.8.4.4",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewTunDialerWithNameservers(tt.args.raw, tt.args.ns1, tt.args.ns2); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewTunDialerWithNameservers() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewTunDialerFromOptions(t *testing.T) {
	options := makeTestingOptions(t, "AES-128-GCM", "sha512")
	type args struct {
		opt *Options
	}
	tests := []struct {
		name string
		args args
		want TunDialer
	}{
		{
			name: "get tundialer from options ok",
			args: args{opt: options},
			want: TunDialer{
				raw: &RawDialer{Options: options},
				ns1: openDNSPrimary,
				ns2: openDNSSecondary,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewTunDialerFromOptions(tt.args.opt); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewTunDialerFromOptions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func mockedDialFn(string, string) (net.Conn, error) {
	conn := makeTestingConnForHandshake("udp", "10.0.0.0", 42)
	return conn, nil
}

type mockRawDialer struct {
	RawDialer
}

func (mrd *mockRawDialer) dial() (*Client, error) {
	return &Client{}, nil
}

func makeTestingClient(opt *Options) vpnClient {
	client := &Client{Opts: opt}
	client.conn = makeTestingConnForHandshake("udp", "10.0.0.1", 42)
	client.tunnel = &tunnel{ip: "10.0.0.1", mtu: 1500}
	return client
}

func makeTestingConnForReadWrite(network, addr string, n int) net.Conn {
	mockAddr := &mocks.Addr{}
	mockAddr.MockString = func() string {
		return addr
	}
	mockAddr.MockNetwork = func() string {
		return network
	}

	mockConn := &mocks.Conn{}
	mockConn.MockLocalAddr = func() net.Addr {
		return mockAddr
	}
	mockConn.MockWrite = func([]byte) (int, error) {
		return n, nil
	}
	mockConn.MockRead = func(b []byte) (int, error) {
		switch mockConn.Count {
		case 0:
			// control message data (to load remote key)
			p := []byte{0x00, 0x00, 0x00, 0x00, 0x02}
			p = append(p, bytes.Repeat([]byte{0x01}, 70)...)
			copy(b[:], p)
			mockConn.Count += 1
			return len(p), nil
		case 1:
			// control message data (pushed options)
			p := []byte("PUSH_REPLY,ifconfig 2.2.2.2")
			copy(b[:], p)
			mockConn.Count += 1
			return len(p), nil
		}

		return 0, nil
	}
	return mockConn
}

func makeTestingRawDialer(t *testing.T) RawDialer {
	raw := RawDialer{
		Options:       makeTestingOptions(t, "AES-128-GCM", "sha512"),
		dialFn:        mockedDialFn,
		clientFactory: makeTestingClient,
	}
	return raw
}

func TestTunDialer_Dial(t *testing.T) {

	raw := makeTestingRawDialer(t)
	mockedRaw := &mockRawDialer{raw}

	orig := initTLSFn
	defer func() {
		initTLSFn = orig
	}()

	initTLSFn = func(*session, *certConfig) (*tls.Config, error) {
		return &tls.Config{InsecureSkipVerify: true}, nil
	}
	tlsHandshakeFn = func(tc *TLSConn, tconf *tls.Config) (net.Conn, error) {
		conn := makeTestingConnForReadWrite("udp", "10.1.1.1", 42)
		return conn, nil
	}

	type fields struct {
		DialFn          DialFunc
		raw             *mockRawDialer
		ns1             string
		ns2             string
		skipDeviceSetup bool
	}
	type args struct {
		network string
		address string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    net.Conn
		wantErr error
	}{
		{
			name: "dial ok with mocked dialFn",
			fields: fields{
				DialFn:          mockedDialFn,
				raw:             mockedRaw,
				ns1:             "8.8.8.8",
				ns2:             "8.8.4.4",
				skipDeviceSetup: true,
			},
			args: args{
				network: "udp",
				address: "10.0.88.88:443",
			},
			wantErr: nil,
		},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			td := TunDialer{
				DialFn:          tt.fields.DialFn,
				raw:             &tt.fields.raw.RawDialer,
				ns1:             tt.fields.ns1,
				ns2:             tt.fields.ns2,
				skipDeviceSetup: tt.fields.skipDeviceSetup,
			}
			conn, err := td.Dial(tt.args.network, tt.args.address)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("TunDialer.Dial() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			conn.Close()
		})
	}
}

func TestTunDialer_DialTimeout(t *testing.T) {
	raw := makeTestingRawDialer(t)
	mockedRaw := &mockRawDialer{raw}
	orig := initTLSFn
	defer func() {
		initTLSFn = orig
	}()
	initTLSFn = func(*session, *certConfig) (*tls.Config, error) {
		return &tls.Config{InsecureSkipVerify: true}, nil
	}
	tlsHandshakeFn = func(tc *TLSConn, tconf *tls.Config) (net.Conn, error) {
		conn := makeTestingConnForReadWrite("udp", "10.1.1.1", 42)
		return conn, nil
	}
	type fields struct {
		DialFn          DialFunc
		raw             *mockRawDialer
		ns1             string
		ns2             string
		skipDeviceSetup bool
	}
	type args struct {
		network string
		address string
		timeout time.Duration
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    net.Conn
		wantErr error
	}{
		{
			name: "dial ok with mocked dialFn",
			fields: fields{
				DialFn:          mockedDialFn,
				raw:             mockedRaw,
				ns1:             "8.8.8.8",
				ns2:             "8.8.4.4",
				skipDeviceSetup: true,
			},
			args: args{
				network: "udp",
				address: "10.0.88.88:443",
				timeout: time.Second,
			},
			wantErr: nil,
		},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			td := TunDialer{
				DialFn:          tt.fields.DialFn,
				raw:             &tt.fields.raw.RawDialer,
				ns1:             tt.fields.ns1,
				ns2:             tt.fields.ns2,
				skipDeviceSetup: true,
			}
			conn, err := td.DialTimeout(tt.args.network, tt.args.address, tt.args.timeout)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("TunDialer.DialTimeout() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			conn.Close()
		})
	}
}

func TestTunDialer_DialContext(t *testing.T) {
	raw := makeTestingRawDialer(t)
	mockedRaw := &mockRawDialer{raw}

	orig := initTLSFn
	defer func() {
		initTLSFn = orig
	}()
	initTLSFn = func(*session, *certConfig) (*tls.Config, error) {
		return &tls.Config{InsecureSkipVerify: true}, nil
	}
	tlsHandshakeFn = func(tc *TLSConn, tconf *tls.Config) (net.Conn, error) {
		conn := makeTestingConnForReadWrite("udp", "10.1.1.1", 42)
		return conn, nil
	}

	type fields struct {
		DialFn          DialFunc
		raw             *mockRawDialer
		ns1             string
		ns2             string
		skipDeviceSetup bool
	}
	type args struct {
		ctx     context.Context
		network string
		address string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    net.Conn
		wantErr error
	}{
		{
			name: "dial ok with mocked dialFn",
			fields: fields{
				DialFn:          mockedDialFn,
				raw:             mockedRaw,
				ns1:             "8.8.8.8",
				ns2:             "8.8.4.4",
				skipDeviceSetup: true,
			},
			args: args{
				ctx:     context.Background(),
				network: "udp",
				address: "10.0.88.88:443",
			},
			wantErr: nil,
		},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			td := TunDialer{
				DialFn:          tt.fields.DialFn,
				raw:             &tt.fields.raw.RawDialer,
				ns1:             tt.fields.ns1,
				ns2:             tt.fields.ns2,
				skipDeviceSetup: true,
			}
			conn, err := td.DialContext(tt.args.ctx, tt.args.network, tt.args.address)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("TunDialer.DialContext() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			conn.Close()
		})
	}
}

func TestNewRawDialer(t *testing.T) {
	type args struct {
		opts *Options
	}
	tests := []struct {
		name string
		args args
		want *RawDialer
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewRawDialer(tt.args.opts); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRawDialer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_device_Up(t *testing.T) {
	tun, _, _ := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.0.0.1")},
		[]netip.Addr{
			netip.MustParseAddr("8.8.8.8"),
			netip.MustParseAddr("4.4.4.4")},
		1500)
	vpn := makeTestinConnFromNetwork("udp")
	d := device{tun: tun, vpn: vpn}
	d.Up()
}
