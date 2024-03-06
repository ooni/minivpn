package config

import (
	"os"
	fp "path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ooni/minivpn/internal/model"
)

func TestNewConfig(t *testing.T) {
	t.Run("default constructor does not fail", func(t *testing.T) {
		c := NewConfig()
		if c.logger == nil {
			t.Errorf("logger should not be nil")
		}
		if c.tracer == nil {
			t.Errorf("tracer should not be nil")
		}
	})
	t.Run("WithLogger sets the logger", func(t *testing.T) {
		testLogger := model.NewTestLogger()
		c := NewConfig(WithLogger(testLogger))
		if c.Logger() != testLogger {
			t.Errorf("expected logger to be set to the configured one")
		}
	})
	t.Run("WithTracer sets the tracer", func(t *testing.T) {
		testTracer := model.HandshakeTracer(model.DummyTracer{})
		c := NewConfig(WithHandshakeTracer(testTracer))
		if c.Tracer() != testTracer {
			t.Errorf("expected tracer to be set to the configured one")
		}
	})

	t.Run("WithConfigFile sets OpenVPNOptions after parsing the configured file", func(t *testing.T) {
		configFile := writeValidConfigFile(t.TempDir())
		c := NewConfig(WithConfigFile(configFile))
		opts := c.OpenVPNOptions()
		if opts.Proto.String() != "udp" {
			t.Error("expected proto udp")
		}
		wantRemote := &Remote{
			IPAddr:   "2.3.4.5",
			Endpoint: "2.3.4.5:1194",
			Protocol: "udp",
		}
		if diff := cmp.Diff(c.Remote(), wantRemote); diff != "" {
			t.Error(diff)
		}
	})

}

var sampleConfigFile = `
remote 2.3.4.5 1194
proto udp
cipher AES-256-GCM
auth SHA512
ca ca.crt
cert cert.pem
key cert.pem
`

func writeValidConfigFile(dir string) string {
	cfg := fp.Join(dir, "config")
	os.WriteFile(cfg, []byte(sampleConfigFile), 0600)
	os.WriteFile(fp.Join(dir, "ca.crt"), []byte("dummy"), 0600)
	os.WriteFile(fp.Join(dir, "cert.pem"), []byte("dummy"), 0600)
	os.WriteFile(fp.Join(dir, "key.pem"), []byte("dummy"), 0600)
	return cfg
}
