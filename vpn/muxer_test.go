package vpn

import (
	"bytes"
	"errors"
	"net"
	"reflect"
	"testing"
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
				conn:    makeTestingConn("udp", "10.0.42.2", 42),
				options: makeTestingOptions("AES-128-GCM", "sha1"),
				tunnel:  &tunnel{},
			},
			want: &muxer{
				conn:    makeTestingConn("udp", "10.0.42.2", 42),
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
			if !bytes.Equal(got.session.RemoteSessionID.Bytes(), tt.want.session.RemoteSessionID.Bytes()) {
				t.Errorf("newMuxerFromOptions() session = %v, want %v", got, tt.want)
			}
			if !bytes.Equal(got.session.LocalSessionID.Bytes(), tt.want.session.LocalSessionID.Bytes()) {
				t.Errorf(
					"newMuxerFromOptions() session. = %v, want %v",
					got.session.LocalSessionID.Bytes(),
					tt.want.session.LocalSessionID.Bytes(),
				)
			}
			if !reflect.DeepEqual(got.options, tt.want.options) {
				t.Errorf("newMuxerFromOptions() options = %v, want %v", got.options, tt.want.options)
			}
		})
	}
}
