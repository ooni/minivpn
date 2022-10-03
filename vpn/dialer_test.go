package vpn

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/ooni/minivpn/vpn/mocks"
	tls "github.com/refraction-networking/utls"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func makeTestingClient(opt *Options) *Client {
	client := &Client{Opts: opt}
	client.conn = makeTestingConnForHandshake("udp", "10.0.0.1", 42)
	client.tunInfo = &tunnelInfo{ip: "10.0.0.1", mtu: 1500}
	client.mux = &mockMuxerForClient{}
	return client
}

func TestNewTunDialer(t *testing.T) {
	opt := makeTestingOptions(t, "AES-128-GCM", "sha512")
	mockClient := makeTestingClient(opt)
	type args struct {
		client *Client
	}
	tests := []struct {
		name string
		args args
		want *TunDialer
	}{
		{
			name: "get dialer ok",
			args: args{
				client: mockClient,
			},
			want: &TunDialer{
				client: mockClient,
				ns1:    openDNSPrimary,
				ns2:    openDNSSecondary,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewTunDialer(tt.args.client)
			if tt.want != nil && got == nil {
				t.Errorf("expected non-nil result")
				return
			}
			if got.client == nil {
				t.Errorf("client should not be nil")
				return
			}
			if !reflect.DeepEqual(got.client.Opts, tt.want.client.Opts) {
				t.Errorf("NewTunDialerFromOptions() = %v, want %v", got, tt.want)
				return
			}
		})
	}
}

func TestNewTunDialerWithNameservers(t *testing.T) {
	opt := makeTestingOptions(t, "AES-128-GCM", "sha512")
	mockClient := makeTestingClient(opt)
	type args struct {
		client *Client
		ns1    string
		ns2    string
	}
	tests := []struct {
		name string
		args args
		want *TunDialer
	}{
		{
			name: "get tundialer with passed nameservers",
			args: args{
				client: mockClient,
				ns1:    "8.8.8.8",
				ns2:    "8.8.4.4",
			},
			want: &TunDialer{
				client: mockClient,
				ns1:    "8.8.8.8",
				ns2:    "8.8.4.4",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewTunDialerWithNameservers(tt.args.client, tt.args.ns1, tt.args.ns2)
			if tt.want != nil && got == nil {
				t.Errorf("expected non-nil result")
				return
			}
			if got.client == nil {
				t.Errorf("client should not be nil")
				return
			}
			if got.ns1 != tt.want.ns1 {
				t.Errorf("NewTunDialerWithNameservers() ns1 = %v, want %v", got.ns1, tt.want.ns1)
			}
			if got.ns2 != tt.want.ns2 {
				t.Errorf("NewTunDialerWithNameservers() ns2 = %v, want %v", got.ns2, tt.want.ns2)
			}
		})
	}
}

type mockDialer struct {
	called bool
}

func (d *mockDialer) DialContext(ctx context.Context, a, b string) (net.Conn, error) {
	d.called = true
	conn := makeTestingConnForHandshake("udp", "10.0.0.0", 42)
	return conn, nil
}

func TestStartNewTunDialerFromOptions(t *testing.T) {
	//opt := makeTestingOptions(t, "AES-128-GCM", "sha512")

	type args struct {
		opt    *Options
		dialer *mockDialer
	}
	tests := []struct {
		name    string
		args    args
		want    *TunDialer
		wantErr error
	}{
		/*
		 {
		 	name: "get tundialer from options calls start and fails on tls handshake",
		 	args: args{
		 		opt:    opt,
		 		dialer: &mockDialer{},
		 	},
		 	want: nil,
		 	// TODO(ainghazal): I'd like to return nil here, but that would force
		 	// me to leak even more internals from the client
		 	// initialization. maybe it's not a good idea to have a
		 	// convenience function that returns an started client after all?
		 	wantErr: ErrBadTLSHandshake,
		 },
		*/
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := StartNewTunDialerFromOptions(tt.args.opt)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("expected error %v, got %v", tt.wantErr, err)
				return
			}
			if tt.want == nil && got == nil {
				return
			}
			if tt.want != nil && got != nil {
				t.Errorf("expected non-nil result")
				return
			}
			if tt.want != nil || got.client == nil {
				t.Errorf("client should not be nil")
				return
			}
			if !tt.args.dialer.called {
				t.Errorf("the mock Dialer has not been called")
				return
			}
			if !reflect.DeepEqual(got.client.Opts, tt.want.client.Opts) {
				t.Errorf("NewTunDialerFromOptions() = %v, want %v", got, tt.want)
				return
			}
		})
	}
}

type mockedDialerContext struct{}

func (md *mockedDialerContext) DialContext(context.Context, string, string) (net.Conn, error) {
	conn := makeTestingConnForHandshake("udp", "10.0.0.0", 42)
	return conn, nil
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

// TODO(https://github.com/ooni/minivpn/issues/28):
// refactor test to use custom dialers
func TestTunDialer_Dial(t *testing.T) {
	opt := makeTestingOptions(t, "AES-128-GCM", "sha512")
	mockClient := makeTestingClient(opt)

	orig := initTLSFn
	defer func() {
		initTLSFn = orig
	}()

	initTLSFn = func(*session, *certConfig) (*tls.Config, error) {
		return &tls.Config{InsecureSkipVerify: true}, nil
	}
	tlsHandshakeFn = func(tc *controlChannelTLSConn, tconf *tls.Config) (net.Conn, error) {
		conn := makeTestingConnForReadWrite("udp", "10.1.1.1", 42)
		return conn, nil
	}

	type fields struct {
		Dialer          DialerContext
		client          *Client
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
				client:          mockClient,
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
				client:          tt.fields.client,
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

// TODO(https://github.com/ooni/minivpn/issues/28):
// refactor test to use custom dialers
func TestTunDialer_DialTimeout(t *testing.T) {
	opt := makeTestingOptions(t, "AES-128-GCM", "sha512")
	mockClient := makeTestingClient(opt)

	orig := initTLSFn
	defer func() {
		initTLSFn = orig
	}()
	initTLSFn = func(*session, *certConfig) (*tls.Config, error) {
		return &tls.Config{InsecureSkipVerify: true}, nil
	}
	tlsHandshakeFn = func(tc *controlChannelTLSConn, tconf *tls.Config) (net.Conn, error) {
		conn := makeTestingConnForReadWrite("udp", "10.1.1.1", 42)
		return conn, nil
	}
	type fields struct {
		client          *Client
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
				client:          mockClient,
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
				client:          tt.fields.client,
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

// TODO(https://github.com/ooni/minivpn/issues/28):
// refactor test to use custom dialers
func TestTunDialer_DialContext(t *testing.T) {
	opt := makeTestingOptions(t, "AES-128-GCM", "sha512")
	mockClient := makeTestingClient(opt)

	orig := initTLSFn
	defer func() {
		initTLSFn = orig
	}()
	initTLSFn = func(*session, *certConfig) (*tls.Config, error) {
		return &tls.Config{InsecureSkipVerify: true}, nil
	}
	tlsHandshakeFn = func(tc *controlChannelTLSConn, tconf *tls.Config) (net.Conn, error) {
		conn := makeTestingConnForReadWrite("udp", "10.1.1.1", 42)
		return conn, nil
	}

	type fields struct {
		client          *Client
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
			name: "dial ok with mocked dialer",
			fields: fields{
				client:          mockClient,
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			td := TunDialer{
				client:          tt.fields.client,
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
