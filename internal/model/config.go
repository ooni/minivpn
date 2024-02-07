package model

import (
	"net"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/runtimex"
)

// Config contains options to initialize the OpenVPN tunnel.
type Config struct {
	// openVPNOptions contains options related to openvpn.
	openvpnOptions *OpenVPNOptions

	// logger will be used to log events.
	logger Logger

	// if a tracer is provided, it will be used to trace the openvpn handshake.
	tracer HandshakeTracer
}

// NewConfig returns a Config ready to intialize a vpn tunnel.
func NewConfig(options ...Option) *Config {
	// TODO(ainghazal): provide a nop-tracer.
	cfg := &Config{
		openvpnOptions: &OpenVPNOptions{},
		logger:         log.Log,
		tracer:         &dummyTracer{},
	}
	for _, opt := range options {
		opt(cfg)
	}
	return cfg
}

// Option is an option you can pass to initialize minivpn.
type Option func(config *Config)

// WithConfigFile configures OpenVPNOptions parsed from the given file.
func WithConfigFile(configPath string) Option {
	return func(config *Config) {
		openvpnOpts, err := ReadConfigFile(configPath)
		runtimex.PanicOnError(err, "cannot parse config file")
		runtimex.PanicIfFalse(openvpnOpts.HasAuthInfo(), "missing auth info")
		config.openvpnOptions = openvpnOpts
	}

}

// WithLogger configures the passed [Logger].
func WithLogger(logger Logger) Option {
	return func(config *Config) {
		config.logger = logger
	}
}

// WithHandshakeTracer configures the passed [HandshakeTracer].
func WithHandshakeTracer(tracer HandshakeTracer) Option {
	return func(config *Config) {
		config.tracer = tracer
	}
}

// Logger returns the configured logger.
func (c *Config) Logger() Logger {
	return c.logger
}

// OpenVPNOptions returns the configured openvpn options.
func (c *Config) OpenVPNOptions() *OpenVPNOptions {
	return c.openvpnOptions
}

// Remote returns the openvpn remote.
func (c *Config) Remote() *Remote {
	return &Remote{
		IPAddr:   c.openvpnOptions.Remote,
		AddrPort: net.JoinHostPort(c.openvpnOptions.Remote, c.openvpnOptions.Port),
		Protocol: c.openvpnOptions.Proto.String(),
	}
}

// Tracer returns the handshake tracer.
func (c *Config) Tracer() HandshakeTracer {
	return c.tracer
}

// Remote has info about the OpenVPNRemote.
type Remote struct {
	IPAddr   string
	AddrPort string
	Protocol string
}
