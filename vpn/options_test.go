package vpn

import (
	"errors"
	"os"
	fp "path/filepath"
	"reflect"
	"testing"
)

func writeDummyCertFiles(d string) {
	os.WriteFile(fp.Join(d, "ca.crt"), []byte("dummy"), 0600)
	os.WriteFile(fp.Join(d, "cert.pem"), []byte("dummy"), 0600)
	os.WriteFile(fp.Join(d, "key.pem"), []byte("dummy"), 0600)
}

func TestOptions_String(t *testing.T) {
	type fields struct {
		Remote     string
		Port       string
		Proto      int
		Username   string
		Password   string
		Ca         string
		Cert       string
		Key        string
		Compress   compression
		Cipher     string
		Auth       string
		TLSMaxVer  string
		ProxyOBFS4 string
		Log        Logger
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name:   "empty cipher",
			fields: fields{},
			want:   "",
		},
		{
			name: "proto tcp",
			fields: fields{
				Cipher: "AES-128-GCM",
				Auth:   "sha512",
				Proto:  1,
			},
			want: "V1,dev-type tun,link-mtu 1549,tun-mtu 1500,proto TCPv4,cipher AES-128-GCM,auth sha512,keysize 128,key-method 2,tls-client",
		},
		{
			name: "compress stub",
			fields: fields{
				Cipher:   "AES-128-GCM",
				Auth:     "sha512",
				Proto:    2,
				Compress: compressionStub,
			},
			want: "V1,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher AES-128-GCM,auth sha512,keysize 128,key-method 2,tls-client,compress stub",
		},
		{
			name: "compress lzo-no",
			fields: fields{
				Cipher:   "AES-128-GCM",
				Auth:     "sha512",
				Proto:    2,
				Compress: compressionLZONo,
			},
			want: "V1,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher AES-128-GCM,auth sha512,keysize 128,key-method 2,tls-client,lzo-comp no",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &Options{
				Remote:     tt.fields.Remote,
				Port:       tt.fields.Port,
				Proto:      tt.fields.Proto,
				Username:   tt.fields.Username,
				Password:   tt.fields.Password,
				CaPath:     tt.fields.Ca,
				CertPath:   tt.fields.Cert,
				KeyPath:    tt.fields.Key,
				Compress:   tt.fields.Compress,
				Cipher:     tt.fields.Cipher,
				Auth:       tt.fields.Auth,
				TLSMaxVer:  tt.fields.TLSMaxVer,
				ProxyOBFS4: tt.fields.ProxyOBFS4,
				Log:        tt.fields.Log,
			}
			if got := o.String(); got != tt.want {
				t.Errorf("Options.string() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetOptionsFromLines(t *testing.T) {
	d := t.TempDir()
	l := []string{
		"remote 0.0.0.0 1194",
		"cipher AES-256-GCM",
		"auth SHA512",
		"ca ca.crt",
		"cert cert.pem",
		"key cert.pem",
	}
	writeDummyCertFiles(d)
	o, err := getOptionsFromLines(l, d)
	if err != nil {
		t.Errorf("Good options should not fail: %s", err)
	}
	if o.Cipher != "AES-256-GCM" {
		t.Errorf("Cipher not what expected")
	}
	if o.Auth != "SHA512" {
		t.Errorf("Auth not what expected")
	}
}

func TestGetOptionsFromLinesInlineCerts(t *testing.T) {
	l := []string{
		"<ca>",
		"ca_string",
		"</ca>",
		"<cert>",
		"cert_string",
		"</cert>",
		"<key>",
		"key_string",
		"</key>",
	}
	o, err := getOptionsFromLines(l, "")
	if err != nil {
		t.Errorf("Good options should not fail: %s", err)
	}
	if string(o.Ca) != "ca_string\n" {
		t.Errorf("Expected ca_string, got: %s.", string(o.Ca))
	}
	if string(o.Cert) != "cert_string\n" {
		t.Errorf("Expected cert_string, got: %s.", string(o.Cert))
	}
	if string(o.Key) != "key_string\n" {
		t.Errorf("Expected key_string, got: %s.", string(o.Key))
	}
}

func TestGetOptionsFromLinesNoFiles(t *testing.T) {
	d := t.TempDir()
	l := []string{
		"ca ca.crt",
	}
	_, err := getOptionsFromLines(l, d)
	if err == nil {
		t.Errorf("Should fail if no files provided")
	}
}

func TestGetOptionsNoCompression(t *testing.T) {
	d := t.TempDir()
	l := []string{
		"compress",
	}
	// should fail if no certs
	// writeDummyCertFiles(d)
	o, err := getOptionsFromLines(l, d)
	if err != nil {
		t.Errorf("Should not fail: compress")
	}
	if o.Compress != "empty" {
		t.Errorf("Expected compress==empty")
	}
}

func TestGetOptionsCompressionStub(t *testing.T) {
	d := t.TempDir()
	l := []string{
		"compress stub",
	}
	// should fail if no certs
	// writeDummyCertFiles(d)
	o, err := getOptionsFromLines(l, d)
	if err != nil {
		t.Errorf("Should not fail: compress stub")
	}
	if o.Compress != "stub" {
		t.Errorf("expected compress==stub")
	}
}

func TestGetOptionsCompressionBad(t *testing.T) {
	d := t.TempDir()
	l := []string{
		"compress foo",
	}
	// should fail if no certs
	// writeDummyCertFiles(d)
	_, err := getOptionsFromLines(l, d)
	if err == nil {
		t.Errorf("Unknown compress: should fail")
	}
}

func TestGetOptionsCompressLZO(t *testing.T) {
	d := t.TempDir()
	l := []string{
		"comp-lzo no",
	}
	// should fail if no certs
	// writeDummyCertFiles(d)
	o, err := getOptionsFromLines(l, d)
	if err != nil {
		t.Errorf("Should not fail: lzo-comp no")
	}
	if o.Compress != "lzo-no" {
		t.Errorf("expected compress=lzo-no")
	}
}

func TestGetOptionsBadRemote(t *testing.T) {
	d := t.TempDir()
	l := []string{
		"remote",
	}
	// should fail if no certs
	// writeDummyCertFiles(d)
	_, err := getOptionsFromLines(l, d)
	if err == nil {
		t.Errorf("Should fail: malformed remote")
	}
}

func TestGetOptionsBadCipher(t *testing.T) {
	d := t.TempDir()
	l := []string{
		"cipher",
	}
	// should fail if no certs
	// writeDummyCertFiles(d)
	_, err := getOptionsFromLines(l, d)
	if err == nil {
		t.Errorf("Should fail: malformed cipher")
	}
	l = []string{
		"cipher AES-111-CBC",
	}
	_, err = getOptionsFromLines(l, d)
	if err == nil {
		t.Errorf("Should fail: bad cipher")
	}
}

func TestGetOptionsComment(t *testing.T) {
	d := t.TempDir()
	l := []string{
		"cipher AES-256-GCM",
		"#cipher AES-128-GCM",
	}
	// should fail if no certs
	// writeDummyCertFiles(d)
	o, err := getOptionsFromLines(l, d)
	if err != nil {
		t.Errorf("Should not fail: commented line")
	}
	if o.Cipher != "AES-256-GCM" {
		t.Errorf("Expected cipher: AES-256-GCM")
	}
}

var dummyConfigFile = []byte(`proto udp
cipher AES-128-GCM
auth SHA1`)

func writeDummyConfigFile(dir string) (string, error) {
	f, err := os.CreateTemp(dir, "tmpfile-")
	if err != nil {
		return "", err
	}
	f.Write(dummyConfigFile)
	return f.Name(), nil
}

func Test_ParseConfigFile(t *testing.T) {
	// parse good file
	f, err := writeDummyConfigFile(t.TempDir())
	if err != nil {
		t.Fatal("ParseConfigFile(): cannot write cert needed for the test")
	}
	o, err := NewOptionsFromFilePath(f)
	if err != nil {
		t.Errorf("ParseConfigFile(): expected err=%v, got=%v", nil, err)
	}
	wantProto := UDPMode
	if o.Proto != wantProto {
		t.Errorf("ParseConfigFile(): expected Proto=%v, got=%v", wantProto, o.Proto)
	}
	wantCipher := "AES-128-GCM"
	if o.Cipher != wantCipher {
		t.Errorf("ParseConfigFile(): expected=%v, got=%v", wantCipher, o.Cipher)
	}

	// expect error when parsing a bad filepath
	_, err = NewOptionsFromFilePath("")
	if err == nil {
		t.Errorf("expected error with empty file")
	}

	_, err = NewOptionsFromFilePath("http://example.com")
	if err == nil {
		t.Errorf("expected error with http uri")
	}
}

func Test_parseProto(t *testing.T) {
	// empty parts
	err := parseProto([]string{}, &Options{})
	wantErr := errBadCfg
	if !errors.Is(err, wantErr) {
		t.Errorf("parseProto(): wantErr: %v, got %v", wantErr, err)
	}

	// two parts
	err = parseProto([]string{"foo", "bar"}, &Options{})
	wantErr = errBadCfg
	if !errors.Is(err, wantErr) {
		t.Errorf("parseProto(): wantErr %v, got %v", wantErr, err)
	}

	// udp
	opt := &Options{}
	err = parseProto([]string{"udp"}, opt)
	if !errors.Is(err, nil) {
		t.Errorf("parseProto(): wantErr: %v, got %v", nil, err)
	}
	if opt.Proto != UDPMode {
		t.Errorf("parseProto(): wantErr %v, got %v", nil, err)
	}

	// tcp
	opt = &Options{}
	err = parseProto([]string{"tcp"}, opt)
	if !errors.Is(err, nil) {
		t.Errorf("parseProto(): wantErr: %v, got %v", nil, err)
	}
	if opt.Proto != TCPMode {
		t.Errorf("parseProto(): wantErr %v, got %v", nil, err)
	}

	// bad
	opt = &Options{}
	err = parseProto([]string{"kcp"}, opt)
	wantErr = errBadCfg
	if !errors.Is(err, wantErr) {
		t.Errorf("parseProto(): wantErr: %v, got %v", errBadCfg, err)
	}

}

func Test_parseProxyOBFS4(t *testing.T) {
	// empty parts
	err := parseProxyOBFS4([]string{}, &Options{})
	wantErr := errBadCfg
	if !errors.Is(err, wantErr) {
		t.Errorf("parseProxyOBFS4(): wantErr: %v, got %v", wantErr, err)
	}

	// obfs4 string
	opt := &Options{}
	obfs4Uri := "obfs4://foobar"
	err = parseProxyOBFS4([]string{obfs4Uri}, opt)
	wantErr = nil
	if !errors.Is(err, wantErr) {
		t.Errorf("parseProxyOBFS4(): wantErr: %v, got %v", wantErr, err)
	}
	if opt.ProxyOBFS4 != obfs4Uri {
		t.Errorf("parseProxyOBFS4(): want %v, got %v", obfs4Uri, opt.ProxyOBFS4)
	}

}

func Test_parseCA(t *testing.T) {
	// more than one part should fail
	err := parseCA([]string{"one", "two"}, &Options{}, "")
	wantErr := errBadCfg
	if !errors.Is(err, wantErr) {
		t.Errorf("parseCA(): want %v, got %v", wantErr, err)
	}

	// empty part should fail
	err = parseCA([]string{}, &Options{}, "")
	wantErr = errBadCfg
	if !errors.Is(err, wantErr) {
		t.Errorf("parseCA(): want %v, got %v", wantErr, err)
	}
}

func Test_parseCert(t *testing.T) {
	// more than one part should fail
	err := parseCert([]string{"one", "two"}, &Options{}, "")
	wantErr := errBadCfg
	if !errors.Is(err, wantErr) {
		t.Errorf("parseCert(): want %v, got %v", wantErr, err)
	}

	// empty part should fail
	err = parseCert([]string{}, &Options{}, "")
	wantErr = errBadCfg
	if !errors.Is(err, wantErr) {
		t.Errorf("parseCert(): want %v, got %v", wantErr, err)
	}

	// non-existent cert should fail
	err = parseCert([]string{"/tmp/nonexistent"}, &Options{}, "")
	wantErr = errBadCfg
	if !errors.Is(err, wantErr) {
		t.Errorf("parseCert(): want %v, got %v", wantErr, err)
	}
}

func Test_parseKey(t *testing.T) {
	// more than one part should fail
	err := parseKey([]string{"one", "two"}, &Options{}, "")
	wantErr := errBadCfg
	if !errors.Is(err, wantErr) {
		t.Errorf("parseKey(): want %v, got %v", wantErr, err)
	}

	// empty part should fail
	err = parseKey([]string{}, &Options{}, "")
	wantErr = errBadCfg
	if !errors.Is(err, wantErr) {
		t.Errorf("parseKey(): want %v, got %v", wantErr, err)
	}

	// non-existent key should fail
	err = parseKey([]string{"/tmp/nonexistent"}, &Options{}, "")
	wantErr = errBadCfg
	if !errors.Is(err, wantErr) {
		t.Errorf("parseKey(): want %v, got %v", wantErr, err)
	}
}

func Test_parseCompress(t *testing.T) {
	// more than one part should fail
	err := parseCompress([]string{"one", "two"}, &Options{})
	wantErr := errBadCfg
	if !errors.Is(err, wantErr) {
		t.Errorf("parseCompress(): want %v, got %v", wantErr, err)
	}
}

func Test_parseCompLZO(t *testing.T) {
	// only "no" is supported
	err := parseCompLZO([]string{"yes"}, &Options{})
	wantErr := errBadCfg
	if !errors.Is(err, wantErr) {
		t.Errorf("parseCompLZO(): want %v, got %v", wantErr, err)
	}
}

func Test_parseOption(t *testing.T) {
	// unknown key should not fail
	err := parseOption(&Options{}, t.TempDir(), "unknownKey", []string{"a", "b"}, 0)
	if err != nil {
		t.Errorf("parseOption(): want %v, got %v", nil, err)
	}
}

func Test_newTunnelInfoFromRemoteOptionsString(t *testing.T) {
	type args struct {
		remoteOpts string
	}
	tests := []struct {
		name string
		args args
		want *tunnelInfo
	}{
		{
			name: "parse good tun-mtu",
			args: args{
				remoteOpts: "foo bar,tun-mtu 1500",
			},
			want: &tunnelInfo{
				mtu: 1500,
			},
		},
		{
			name: "empty string",
			args: args{
				remoteOpts: "",
			},
			want: &tunnelInfo{},
		},
		{
			name: "empty field",
			args: args{
				remoteOpts: "tun-mtu 1200,,",
			},
			want: &tunnelInfo{
				mtu: 1200,
			},
		},
		{
			name: "extra space",
			args: args{
				remoteOpts: "tun-mtu  1200",
			},
			want: &tunnelInfo{},
		},
		{
			name: "mtu not an int",
			args: args{
				remoteOpts: "tun-mtu aaa",
			},
			want: &tunnelInfo{},
		},
		{
			name: "entry with single field",
			args: args{
				remoteOpts: "bad",
			},
			want: &tunnelInfo{},
		},
		{
			name: "entries with single field",
			args: args{
				remoteOpts: "bad,worse",
			},
			want: &tunnelInfo{},
		},
		{
			name: "tun-mtu no value",
			args: args{
				remoteOpts: "tun-mtu",
			},
			want: &tunnelInfo{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newTunnelInfoFromRemoteOptionsString(tt.args.remoteOpts); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseRemoteOptions() = %v, want %v", got, tt.want)
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
		want map[string][]string
	}{
		{
			name: "do parse tunnel ip",
			args: args{[]byte("foo bar,ifconfig 10.0.0.3,")},
			want: map[string][]string{
				"foo":      []string{"bar"},
				"ifconfig": []string{"10.0.0.3"},
			},
		},
		{
			name: "empty string",
			args: args{[]byte{}},
			want: map[string][]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pushedOptionsAsMap(tt.args.pushedOptions); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pushedOptionsAsMap() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseAuth(t *testing.T) {
	type args struct {
		p []string
		o *Options
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name:    "should fail with empty array",
			args:    args{[]string{}, &Options{}},
			wantErr: errBadCfg,
		},
		{
			name:    "should fail with 2-element array",
			args:    args{[]string{"foo", "bar"}, &Options{}},
			wantErr: errBadCfg,
		},
		{
			name:    "should fail with lowercase option",
			args:    args{[]string{"sha1"}, &Options{}},
			wantErr: errBadCfg,
		},
		{
			name:    "should fail with unknown option",
			args:    args{[]string{"SHA666"}, &Options{}},
			wantErr: errBadCfg,
		},
		{
			name:    "should not fail with good option",
			args:    args{[]string{"SHA512"}, &Options{}},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := parseAuth(tt.args.p, tt.args.o); !errors.Is(err, tt.wantErr) {
				t.Errorf("parseAuth() error = %v, wantErr %v", err, tt.wantErr)
			}

		})
	}
}

func Test_parseAuthUser(t *testing.T) {
	makeCreds := func(credStr string) string {
		f, err := os.CreateTemp(t.TempDir(), "tmpfile-")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(credStr)); err != nil {
			t.Fatal(err)
		}
		return f.Name()
	}

	baseDir := func() string {
		return os.TempDir()
	}

	type args struct {
		p []string
		o *Options
		d string
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name: "parse good auth",
			args: args{
				p: []string{makeCreds("foo\nbar\n")},
				o: &Options{},
				d: baseDir(),
			},
			wantErr: nil,
		},
		{
			name: "path traversal should fail",
			args: args{
				p: []string{"/tmp/../etc/passwd"},
				o: &Options{},
				d: baseDir(),
			},
			wantErr: errBadCfg,
		},
		{
			name: "parse empty file should fail",
			args: args{
				p: []string{""},
				o: &Options{},
				d: baseDir(),
			},
			wantErr: errBadCfg,
		},
		{
			name: "parse empty parts should fail",
			args: args{
				p: []string{},
				o: &Options{},
				d: baseDir(),
			},
			wantErr: errBadCfg,
		},
		{
			name: "parse less than two lines should fail",
			args: args{
				p: []string{makeCreds("foo\n")},
				o: &Options{},
				d: baseDir(),
			},
			wantErr: errBadCfg,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := parseAuthUser(tt.args.p, tt.args.o, tt.args.d); !errors.Is(err, tt.wantErr) {
				t.Errorf("parseAuthUser() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TODO(ainghazal): return options object so that it's testable too
func Test_parseTLSVerMax(t *testing.T) {
	type args struct {
		p []string
		o *Options
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name:    "nil options should fail",
			args:    args{},
			wantErr: errBadInput,
		},
		{
			name:    "default",
			args:    args{o: &Options{}},
			wantErr: nil,
		},
		{
			name:    "default with good tls opt",
			args:    args{p: []string{"1.2"}, o: &Options{}},
			wantErr: nil,
		},
		{
			// FIXME this case should probably fail
			name:    "default with too many parts",
			args:    args{p: []string{"1.2", "1.3"}, o: &Options{}},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := parseTLSVerMax(tt.args.p, tt.args.o); !errors.Is(err, tt.wantErr) {
				t.Errorf("parseTLSVerMax() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_proto_String(t *testing.T) {
	tests := []struct {
		name string
		p    proto
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.String(); got != tt.want {
				t.Errorf("proto.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getCredentialsFromFile(t *testing.T) {
	makeCreds := func(credStr string) string {
		f, err := os.CreateTemp(t.TempDir(), "tmpfile-")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(credStr)); err != nil {
			t.Fatal(err)
		}
		return f.Name()
	}

	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr error
	}{
		{
			name:    "should fail with non-existing file",
			args:    args{"/tmp/nonexistent"},
			want:    nil,
			wantErr: errBadCfg,
		},
		{
			name:    "should fail with empty file",
			args:    args{makeCreds("")},
			want:    nil,
			wantErr: errBadCfg,
		},
		{
			name:    "should fail with empty user",
			args:    args{makeCreds("\n\n")},
			want:    nil,
			wantErr: errBadCfg,
		},
		{
			name:    "should fail with empty pass",
			args:    args{makeCreds("user\n\n")},
			want:    nil,
			wantErr: errBadCfg,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getCredentialsFromFile(tt.args.path)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("getCredentialsFromFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getCredentialsFromFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isSubdir(t *testing.T) {
	type args struct {
		parent string
		sub    string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "sunny path",
			args: args{
				parent: "/foo/bar",
				sub:    "/foo/bar/baz",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "same dir",
			args: args{
				parent: "/foo/bar",
				sub:    "/foo/bar",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "same dir w/ slash",
			args: args{
				parent: "/foo/bar",
				sub:    "/foo/bar/",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "not subdir",
			args: args{
				parent: "/foo/bar",
				sub:    "/foo",
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "path traversal",
			args: args{
				parent: "/foo/bar",
				sub:    "/foo/bar/./../",
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "path traversal with .",
			args: args{
				parent: ".",
				sub:    "/etc/",
			},
			want:    false,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := isSubdir(tt.args.parent, tt.args.sub)
			if (err != nil) != tt.wantErr {
				t.Errorf("isSubdir() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("isSubdir() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_newTunnelInfoFromPushedOptions(t *testing.T) {
	type args struct {
		opts map[string][]string
	}
	tests := []struct {
		name string
		args args
		want *tunnelInfo
	}{
		{
			name: "get route",
			args: args{
				map[string][]string{
					"route": []string{"1.1.1.1"},
				},
			},
			want: &tunnelInfo{
				gw: "1.1.1.1",
			},
		},
		{
			name: "get route from gw",
			args: args{
				map[string][]string{
					"route-gateway": []string{"1.1.2.2"},
				},
			},
			want: &tunnelInfo{
				gw: "1.1.2.2",
			},
		},
		{
			name: "get ip",
			args: args{
				map[string][]string{
					"ifconfig": []string{"1.1.3.3", "foo", "bar"},
				},
			},
			want: &tunnelInfo{
				ip: "1.1.3.3",
			},
		},
		{
			name: "get ip and route",
			args: args{
				map[string][]string{
					"ifconfig":      []string{"1.1.3.3", "foo", "bar"},
					"route":         []string{"1.1.1.1"},
					"route-gateway": []string{"1.1.2.2"},
				},
			},
			want: &tunnelInfo{
				ip: "1.1.3.3",
				gw: "1.1.1.1",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newTunnelInfoFromPushedOptions(tt.args.opts); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newTunnelInfoFromPushedOptions() = %v, want %v", got, tt.want)
			}
		})
	}
}
