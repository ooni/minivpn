package obfs4

import (
	"errors"
	"net/url"
	"reflect"
	"testing"
)

func TestNewProxyNodeFromURI(t *testing.T) {
	type args struct {
		uri string
	}
	tests := []struct {
		name    string
		args    args
		want    *ProxyNode
		wantErr error
	}{
		{
			name:    "empty uri returns error",
			args:    args{""},
			want:    &ProxyNode{},
			wantErr: errBadProxyURI,
		},
		{
			name:    "bad scheme returns error",
			args:    args{"http://server/"},
			want:    &ProxyNode{},
			wantErr: errBadProxyURI,
		},
		{
			name:    "file scheme returns error",
			args:    args{"file://foo/bar/baz"},
			want:    &ProxyNode{},
			wantErr: errBadProxyURI,
		},
		{
			name:    "empty port returns error",
			args:    args{"obfs4://foo/bar/baz"},
			want:    &ProxyNode{},
			wantErr: errBadProxyURI,
		},
		{
			name:    "empty hostname returns error",
			args:    args{"obfs4://:222/bar/baz"},
			want:    &ProxyNode{},
			wantErr: errBadProxyURI,
		},
		{
			name: "happy path does not return error",
			args: args{"obfs4://proxy:4444?cert=deadbeef&iat-mode=0"},
			want: &ProxyNode{
				Addr:     "proxy:4444",
				Protocol: "obfs4",
				url: func() *url.URL {
					u, _ := url.Parse("obfs4://proxy:4444?cert=deadbeef&iat-mode=0")
					return u
				}(),
				Values: url.Values(map[string][]string{
					"cert":     []string{"deadbeef"},
					"iat-mode": []string{"0"},
				}),
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewProxyNodeFromURI(tt.args.uri)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("NewProxyNodeFromURI() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewProxyNodeFromURI() = %v, want %v", got, tt.want)
			}
		})
	}
}
