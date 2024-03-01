package tlssession

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ooni/minivpn/internal/model"
)

func Test_NewTunnelInfoFromRemoteOptionsString(t *testing.T) {
	type args struct {
		remoteOpts remoteOptions
	}
	tests := []struct {
		name string
		args args
		want *model.TunnelInfo
	}{
		{
			name: "get route",
			args: args{
				remoteOptions{
					"route": []string{"1.1.1.1"},
				},
			},
			want: &model.TunnelInfo{
				GW: "1.1.1.1",
			},
		},
		{
			name: "get route from gw",
			args: args{
				remoteOptions{
					"route-gateway": []string{"1.1.2.2"},
				},
			},
			want: &model.TunnelInfo{
				GW: "1.1.2.2",
			},
		},
		{
			name: "get ip",
			args: args{
				remoteOptions{
					"ifconfig": []string{"1.1.3.3", "255.255.255.0"},
				},
			},
			want: &model.TunnelInfo{
				IP:      "1.1.3.3",
				NetMask: "255.255.255.0",
			},
		},
		{
			name: "get ip and route",
			args: args{
				remoteOptions{
					"ifconfig":      []string{"10.0.8.1", "255.255.255.0"},
					"route":         []string{"1.1.3.3"},
					"route-gateway": []string{"1.1.2.2"},
				},
			},
			want: &model.TunnelInfo{
				IP:      "10.0.8.1",
				NetMask: "255.255.255.0",
				GW:      "1.1.3.3",
			},
		},
		{
			name: "empty map",
			args: args{
				remoteOpts: remoteOptions{},
			},
			want: &model.TunnelInfo{},
		},
		{
			name: "entries with nil value field",
			args: args{
				remoteOpts: remoteOptions{"bad": nil},
			},
			want: &model.TunnelInfo{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diff := cmp.Diff(newTunnelInfoFromPushedOptions(tt.args.remoteOpts), tt.want)
			if diff != "" {
				t.Error(diff)
			}
		})
	}
}

func Test_pushedOptionsAsMap(t *testing.T) {
	type args struct {
		pushedOptions []byte
	}
	tests := []struct {
		name string
		args args
		want remoteOptions
	}{
		{
			name: "do parse tunnel ip",
			args: args{[]byte("foo bar,ifconfig 10.0.0.3,")},
			want: remoteOptions{
				"foo":      []string{"bar"},
				"ifconfig": []string{"10.0.0.3"},
			},
		},
		{
			name: "empty string",
			args: args{[]byte{}},
			want: remoteOptions{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(pushedOptionsAsMap(tt.args.pushedOptions), tt.want); diff != "" {
				t.Error(cmp.Diff(pushedOptionsAsMap(tt.args.pushedOptions), tt.want))
			}
		})
	}
}

func Test_parseServerControlMessage(t *testing.T) {
	serverRespHex := "0000000002a490a20a83086e255b4d6c2a10ee9c488d683d1a1337bd4b32b24196a49c98632f00fddcab2c261cb6efae333eed9e1a7f83f3095a0da79b7a6f4709fe1ae040008856342c6465762d747970652074756e2c6c696e6b2d6d747520313535312c74756e2d6d747520313530302c70726f746f2054435076345f5345525645522c636970686572204145532d3235362d47434d2c61757468205b6e756c6c2d6469676573745d2c6b657973697a65203235362c6b65792d6d6574686f6420322c746c732d73657276657200"
	wantOptions := "V4,dev-type tun,link-mtu 1551,tun-mtu 1500,proto TCPv4_SERVER,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-server"
	wantRandom1, _ := hex.DecodeString("a490a20a83086e255b4d6c2a10ee9c488d683d1a1337bd4b32b24196a49c9863")
	wantRandom2, _ := hex.DecodeString("2f00fddcab2c261cb6efae333eed9e1a7f83f3095a0da79b7a6f4709fe1ae040")

	msg, _ := hex.DecodeString(serverRespHex)
	gotKeySource, gotOptions, err := parseServerControlMessage(msg)
	if err != nil {
		t.Errorf("expected null error, got %v", err)
	}
	if wantOptions != gotOptions {
		t.Errorf("parseServerControlMessage(). got options = %v, want options %v", gotOptions, wantOptions)
	}
	if !bytes.Equal(wantRandom1, gotKeySource.R1[:]) {
		t.Errorf("parseServerControlMessage(). got R1 = %v, want %v", gotKeySource.R1, wantRandom1)
	}
	if !bytes.Equal(wantRandom2, gotKeySource.R2[:]) {
		t.Errorf("parseServerControlMessage(). got R2 = %v, want %v", gotKeySource.R2, wantRandom2)
	}
}
