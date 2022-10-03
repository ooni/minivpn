package vpn

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/martian/mitm"
	"github.com/ooni/minivpn/vpn/mocks"
	tls "github.com/refraction-networking/utls"
)

func makeDummyOptionsForCertPaths() *Options {
	return &Options{
		CertPath: "aa",
		KeyPath:  "aa",
		CaPath:   "aa",
	}
}

// TODO(ainghazal): many of these tests right now create certs, which is costly
// bacause creating a CA each time is expensive.
// I should mock any certs for the tests that do not need to actually verify
// the cert chain.

func Test_initTLS(t *testing.T) {
	type args struct {
		session *session
		cfg     *certConfig
	}
	tests := []struct {
		name    string
		args    args
		want    *tls.Config
		wantErr error
	}{
		{
			name: "empty opts should fail",
			args: args{
				session: makeTestingSession(),
			},
			want:    nil,
			wantErr: errBadInput,
		},
		{
			name: "empty session should fail",
			args: args{
				cfg: func() *certConfig {
					crt, err := writeTestingCerts(t.TempDir())
					if err != nil {
						t.Errorf("initTLS() cannot create certs for test %v", err.Error())
					}
					cfg, err := newCertConfigFromOptions(&Options{
						CertPath: crt.cert,
						KeyPath:  crt.key,
						CaPath:   crt.ca,
					})
					if err != nil {
						t.Errorf("initTLS() cannot load config from opts %v", err.Error())
					}
					return cfg
				}(),
			},
			want:    nil,
			wantErr: errBadInput,
		},
		{
			name: "default tls config should not fail with proper cert paths",
			args: args{
				session: makeTestingSession(),
				cfg: func() *certConfig {
					c, _ := writeTestingCerts("")
					cfg, err := newCertConfigFromOptions(
						&Options{
							CertPath: c.cert,
							KeyPath:  c.key,
							CaPath:   c.ca,
						})
					if err != nil {
						t.Errorf("error while testing: %v", err)
					}
					return cfg
				}(),
			},
			want:    nil,
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := initTLS(tt.args.session, tt.args.cfg)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("initTLS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want == nil {
				return
			}
			if !reflect.DeepEqual(got.InsecureSkipVerify, tt.want.InsecureSkipVerify) {
				t.Errorf("initTLS() InsecureSkipVerify = %v, want %v", got.InsecureSkipVerify, tt.want.InsecureSkipVerify)
				return
			}
		})
	}
}

var pemTestingKey = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC/vw0YScdbP2wg
3M+N6BlsCQePUVFlyLh3faPtfqKTeWfyMYhGMeUE4fMcO1H0l7b/+zfwfA85AhlT
dU152AXvizBidnaQXwVxsxzLPiPxn3qH5KxD72vkMHMyUrRh/tdJzIj1bqlCiLcw
SK5EDPMwuUSAIk7evRzLUdGu1JkUxi7xox03R5rvC8ZohAPSRxFAg6rajkk7HlUi
BepNz5PRlPGJ0Kfn0oa/BF+5F3Y4WU+75r9tK+H691eRL65exTGrYIOZE9Rd6i8C
S3WoFNmlO6tv0HMAh/GYR6/mrekOkSZdjNIbDfcNiFsvNtMIO9jztd7g/3BcQg/3
eFydHplrAgMBAAECggEAM8lBnCGw+e/zIB0C4WyiEQ+PPyHTPg4r4/nG4EmnVvUf
IcZG685l8B+mLSXISKsA/bm3rfeTlO4AMQ4pUpMJZ1zMQIuGEg/XxJF/YVTzGDre
OP2FmQN8vDBprFmx5hWRx5i6FK9Cf3m1IBFBH5fvxmUDHygk7PteX3tFilZY0ccM
TpK8nOOpbbK/8S8dC6ePXYgjamLotAnKdgKnpmxQjiprsRAWiOr7DFdjMLCUyZkC
NYwRszVNX84wLOFNzFdU653gFKNcJ/8NI2MBQ5EaBMWOcxNgdfBtCXE9GwQVNzp2
tjTt2QYbTdaw6LAMKgrWgaZBp0VSK4WTlYLifwrSQQKBgQD4Ah39r/l+QyTLwr6d
AkMp/rgpOYzvaRzuUcZnObvi8yfFlJJ6EM4zfNICXNexdqeL+WTaSV1yuc4/rsRx
nAgXklgz2UpATccLJ7JrCDsWgZm71tfUWQM5IbMgkyVixwGYiTsW+kMxFD0n2sNK
sPkEgr2IiSEDfjzTf0LPr7sLyQKBgQDF7NCTTEp92FSz5OcKNSI7iH+lsVgV+U88
Widc/thn/vRnyRqpvyjUvl9D9jMTz2/9DiV06lCYfN8KpknCb3jCWY5cjmOSZQTs
oHQQX145Exe8cj2z+66QK6CsE1tlUC99Y684hn+eDlLMIQGMtRz8aSYb8oZo68sM
hcTaP8CtkwKBgQDK0RhrrWyQWCKQS9uMFRyODFPYysq5wzE4qEFji3BeodFFoEHF
d1bZ/lrUOc7evxU3wCU86kB0oQTNSYQ3EI4BkNl21V0Gh1Seh8E+DIYd2rC5T3JD
ouOi5i9SFWO+itaAQsHDAbjPOyjkHeAVhfKvQKf1L4eDDsp5f5pItAJ4GQKBgDvF
EwuYW1p7jMCynG7Bsu/Ffb68unwQSLRSCVcVAqcNICODYJDoUF1GjCBK5gvSdeA2
eGtBI0uZUgW2R8n2vcH7J3md6kXYSc9neQVEt4CG2oEnAqkqlQGmmyO7yLrkpyK3
ir+IJlvFuY05Xm1ueC1lV4PTDnH62tuSPesmm3oPAoGBANsj/l6xgcMZK6VKZHGV
gG59FoMudCvMP1pITJh+TQPIJbD4TgYnDUG7z14zrYhxChWHYysVrIT35Iuu7k6S
JlkPybAiLmv2nulx9fRkTzcGgvPtG3iHS/WQLvr9umWrfmQYMMW1Udr0IdflS1Sk
fIeuXWkQrCE24uKSInkRupLO
-----END PRIVATE KEY-----`)

var pemTestingCertificate = []byte(`-----BEGIN CERTIFICATE-----
MIIDjTCCAnUCFGb3X7au5DHHCSd8n6e5vG1/HGtyMA0GCSqGSIb3DQEBCwUAMIGB
MQswCQYDVQQGEwJOWjELMAkGA1UECAwCTk8xEjAQBgNVBAcMCUludGVybmV0ejEN
MAsGA1UECgwEQW5vbjENMAsGA1UECwwEcm9vdDESMBAGA1UEAwwJbG9jYWxob3N0
MR8wHQYJKoZIhvcNAQkBFhB1c2VyQGV4YW1wbGUuY29tMB4XDTIyMDUyMDE4Mzk0
N1oXDTIyMDYxOTE4Mzk0N1owgYMxCzAJBgNVBAYTAk5aMQswCQYDVQQIDAJOTzES
MBAGA1UEBwwJSW50ZXJuZXR6MQ0wCwYDVQQKDARBbm9uMQ8wDQYDVQQLDAZzZXJ2
ZXIxEjAQBgNVBAMMCWxvY2FsaG9zdDEfMB0GCSqGSIb3DQEJARYQdXNlckBleGFt
cGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL+/DRhJx1s/
bCDcz43oGWwJB49RUWXIuHd9o+1+opN5Z/IxiEYx5QTh8xw7UfSXtv/7N/B8DzkC
GVN1TXnYBe+LMGJ2dpBfBXGzHMs+I/GfeofkrEPva+QwczJStGH+10nMiPVuqUKI
tzBIrkQM8zC5RIAiTt69HMtR0a7UmRTGLvGjHTdHmu8LxmiEA9JHEUCDqtqOSTse
VSIF6k3Pk9GU8YnQp+fShr8EX7kXdjhZT7vmv20r4fr3V5Evrl7FMatgg5kT1F3q
LwJLdagU2aU7q2/QcwCH8ZhHr+at6Q6RJl2M0hsN9w2IWy820wg72PO13uD/cFxC
D/d4XJ0emWsCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAGt+m0kwuULOVEr7QvbOI
6pxEd9AysxWxGzGBM6G9jrhlgch10wWuhDZq0LqahlWQ8DK9Kjg+pHEYYN8B1m0L
2lloFpXb+AXJR9RKsBr4iU2HdJkPIAwYlDhPUTeskfWP61JGGQC6oem3UXCbLldE
VxcY3vSifP9/pIyjHVULa83FQwwsseavav3NvBgYIyglz+BLl6azMdFLXyzGzEUv
iiN6MdNrJ34iDKHCYSlNvJktJY91eTsQ1GLYD6O9C5KrCJRp0ibQ1keSE7vdhnTY
doKeoNOwq224DcktFdFAYnOM/q3dKxz3m8TsM5OLel4kebqDovPt0hJl2Wwwx43k
0A==
-----END CERTIFICATE-----`)

var pemTestingCa = []byte(`-----BEGIN CERTIFICATE-----
MIID5TCCAs2gAwIBAgIUecMREJYMxFeQEWNBRSCM1x/pAEIwDQYJKoZIhvcNAQEL
BQAwgYExCzAJBgNVBAYTAk5aMQswCQYDVQQIDAJOTzESMBAGA1UEBwwJSW50ZXJu
ZXR6MQ0wCwYDVQQKDARBbm9uMQ0wCwYDVQQLDARyb290MRIwEAYDVQQDDAlsb2Nh
bGhvc3QxHzAdBgkqhkiG9w0BCQEWEHVzZXJAZXhhbXBsZS5jb20wHhcNMjIwNTIw
MTgzOTQ3WhcNMjIwNjE5MTgzOTQ3WjCBgTELMAkGA1UEBhMCTloxCzAJBgNVBAgM
Ak5PMRIwEAYDVQQHDAlJbnRlcm5ldHoxDTALBgNVBAoMBEFub24xDTALBgNVBAsM
BHJvb3QxEjAQBgNVBAMMCWxvY2FsaG9zdDEfMB0GCSqGSIb3DQEJARYQdXNlckBl
eGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMxO6abV
xOy/2VuekAAvJnM2bFIpqSoWK1uMDHJc7NRWVPy2UFaDvCL2g+CSqEyqMN0NI0El
J2cIAgUYOa0+wHJWQhAL60veR6ew9JfIDk3S7YNeKzUGgrRzKvTLdms5mL8fZpT+
GFwHprx58EZwg2TDQ6bGdThsSYNbx72PRngIOl5k6NWdIgd0wiAAYIpNQQUc8rDC
IG4VvoitbpzYcAFCxCVGivodLP02pk2hokbidnLyTj5wIVTccA3u9FeEq2+IIAfr
OW+3LjCpH9SC+3qPjA0UHv2bCLMVzIp86lUsbx6Qcoy0RPh5qC28cLk19wQj5+pw
XtOeL90d2Hokf40CAwEAAaNTMFEwHQYDVR0OBBYEFNuQwyljbQs208ZCI5NFuzvo
1ez8MB8GA1UdIwQYMBaAFNuQwyljbQs208ZCI5NFuzvo1ez8MA8GA1UdEwEB/wQF
MAMBAf8wDQYJKoZIhvcNAQELBQADggEBAHPkGlDDq79rdxFfbt0dMKm1dWZtPlZl
iIY9Pcet/hgf69OKXwb4h3E0IjFW7JHwo4Bfr4mqrTQLTC1qCRNEMC9XUyc4neQy
3r2LRk+D7XAN1zwL6QPw550ukbLk4R4I1xQr+9Sap9h0QUaJj5tts6XSzhZ1AylJ
HgmkOnPOpcIWm+yUMEDESGnhE8hfXR1nhb5lLrg2HIqp9qRRH1w/wc7jG3bYV3jg
S5nL4GaRzx84PB1HWONlh0Wp7KBk2j6Lp0acoJwI2mHJcJoOPpaYiWWYNNTjMv2/
XXNUizTI136liavLslSMoYkjYAun+5HOux/keA1L+lm2XeG06Ew1qS4=
-----END CERTIFICATE-----`)

type testingCert struct {
	cert string
	key  string
	ca   string
}

func writeTestingCerts(dir string) (testingCert, error) {
	certFile, err := os.CreateTemp(dir, "tmpfile-")
	if err != nil {
		return testingCert{}, err
	}
	certFile.Write(pemTestingCertificate)

	keyFile, err := os.CreateTemp(dir, "tmpfile-")
	if err != nil {
		return testingCert{}, err
	}
	keyFile.Write(pemTestingKey)

	caFile, err := os.CreateTemp(dir, "tmpfile-")
	if err != nil {
		return testingCert{}, err
	}
	caFile.Write(pemTestingCa)

	testingCert := testingCert{
		cert: certFile.Name(),
		key:  keyFile.Name(),
		ca:   caFile.Name(),
	}
	return testingCert, nil
}

func writeTestingCertsBadCAFile(dir string) (testingCert, error) {
	certFile, err := os.CreateTemp(dir, "tmpfile-")
	if err != nil {
		return testingCert{}, err
	}
	certFile.Write(pemTestingCertificate)

	keyFile, err := os.CreateTemp(dir, "tmpfile-")
	if err != nil {
		return testingCert{}, err
	}
	keyFile.Write(pemTestingKey)

	caFile, err := os.CreateTemp(dir, "tmpfile-")
	if err != nil {
		return testingCert{}, err
	}
	caFile.Write(pemTestingCa[:len(pemTestingCa)-10])

	testingCert := testingCert{
		cert: certFile.Name(),
		key:  keyFile.Name(),
		ca:   caFile.Name() + "-non-existent",
	}
	return testingCert, nil
}

func writeTestingCertsBadCA(dir string) (testingCert, error) {
	certFile, err := os.CreateTemp(dir, "tmpfile-")
	if err != nil {
		return testingCert{}, err
	}
	certFile.Write(pemTestingCertificate)

	keyFile, err := os.CreateTemp(dir, "tmpfile-")
	if err != nil {
		return testingCert{}, err
	}
	keyFile.Write(pemTestingKey)

	caFile, err := os.CreateTemp(dir, "tmpfile-")
	if err != nil {
		return testingCert{}, err
	}
	caFile.Write(pemTestingCa[:len(pemTestingCa)-10])

	testingCert := testingCert{
		cert: certFile.Name(),
		key:  keyFile.Name(),
		ca:   caFile.Name(),
	}
	return testingCert, nil
}

func writeTestingCertsBadKey(dir string) (testingCert, error) {
	certFile, err := os.CreateTemp(dir, "tmpfile-")
	if err != nil {
		return testingCert{}, err
	}
	certFile.Write(pemTestingCertificate)

	keyFile, err := os.CreateTemp(dir, "tmpfile-")
	if err != nil {
		return testingCert{}, err
	}
	keyFile.Write(pemTestingKey[:len(pemTestingKey)-10])

	caFile, err := os.CreateTemp(dir, "tmpfile-")
	if err != nil {
		return testingCert{}, err
	}
	caFile.Write(pemTestingCa)

	testingCert := testingCert{
		cert: certFile.Name(),
		key:  keyFile.Name(),
		ca:   caFile.Name(),
	}
	return testingCert, nil
}

func writeTestingCertsBadCert(dir string) (testingCert, error) {
	certFile, err := os.CreateTemp(dir, "tmpfile-")
	if err != nil {
		return testingCert{}, err
	}
	certFile.Write(pemTestingCertificate[:len(pemTestingCertificate)-10])

	keyFile, err := os.CreateTemp(dir, "tmpfile-")
	if err != nil {
		return testingCert{}, err
	}
	keyFile.Write(pemTestingKey[:len(pemTestingKey)-10])

	caFile, err := os.CreateTemp(dir, "tmpfile-")
	if err != nil {
		return testingCert{}, err
	}
	caFile.Write(pemTestingCa)

	testingCert := testingCert{
		cert: certFile.Name(),
		key:  keyFile.Name(),
		ca:   caFile.Name(),
	}
	return testingCert, nil
}

func Test_loadCertAndCAFromPath(t *testing.T) {
	type args struct {
		pth certPaths
	}
	tests := []struct {
		name    string
		args    args
		want    *certConfig
		wantErr error
	}{
		{
			name: "bad ca (non existent file) should fail",
			args: func() args {
				crt, err := writeTestingCertsBadCAFile(t.TempDir())
				if err != nil {
					t.Errorf("error while testing: %v", err)
				}
				return args{pth: certPaths{crt.cert, crt.key, crt.ca}}

			}(),
			want:    nil,
			wantErr: ErrBadCA,
		},
		{
			name: "bad ca (malformed) should fail",
			args: func() args {
				crt, err := writeTestingCertsBadCA(t.TempDir())
				if err != nil {
					t.Errorf("error while testing: %v", err)
				}
				return args{pth: certPaths{crt.cert, crt.key, crt.ca}}

			}(),
			want:    nil,
			wantErr: ErrBadCA,
		},
		{
			name: "bad key",
			args: func() args {
				crt, err := writeTestingCertsBadKey(t.TempDir())
				if err != nil {
					t.Errorf("error while testing: %v", err)
				}
				return args{pth: certPaths{crt.cert, crt.key, crt.ca}}

			}(),
			want:    nil,
			wantErr: ErrBadKeypair,
		},
		{
			name: "bad cert",
			args: func() args {
				crt, err := writeTestingCertsBadCert(t.TempDir())
				if err != nil {
					t.Errorf("error while testing: %v", err)
				}
				return args{pth: certPaths{crt.cert, crt.key, crt.ca}}

			}(),
			want:    nil,
			wantErr: ErrBadKeypair,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := loadCertAndCAFromPath(tt.args.pth)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("loadCertAndCA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("loadCertAndCA() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_loadCertAndCAFromBytes(t *testing.T) {
	type args struct {
		crt certBytes
	}
	tests := []struct {
		name    string
		args    args
		want    *certConfig
		wantErr error
	}{
		{
			name: "bad ca should fail",
			args: args{crt: certBytes{
				ca:   pemTestingCa[:len(pemTestingCa)-10],
				cert: pemTestingCertificate,
				key:  pemTestingKey}},
			want:    nil,
			wantErr: ErrBadCA,
		},
		{
			name: "bad cert should fail",
			args: args{crt: certBytes{
				ca:   pemTestingCa,
				cert: pemTestingCertificate[:len(pemTestingCertificate)-10],
				key:  pemTestingKey}},
			want:    nil,
			wantErr: ErrBadKeypair,
		},
		{
			name: "bad key should fail",
			args: args{crt: certBytes{
				ca:   pemTestingCa,
				cert: pemTestingCertificate,
				key:  pemTestingKey[10:]}},
			want:    nil,
			wantErr: ErrBadKeypair,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := loadCertAndCAFromBytes(tt.args.crt)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("loadCertAndCAFromBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("loadCertAndCAFromBytes() = %v, want %v", got, tt.want)
			}
		})
	}
	t.Run("sunny path should not fail", func(t *testing.T) {
		crt := certBytes{
			ca:   pemTestingCa,
			cert: pemTestingCertificate,
			key:  pemTestingKey,
		}
		_, err := loadCertAndCAFromBytes(crt)
		if err != nil {
			t.Errorf("loadCertAndCAFromBytes() err = %v, want %v", err, nil)
		}
	})
}

func Test_initTLSLoadTestCertificates(t *testing.T) {

	t.Run("default options should not fail", func(t *testing.T) {
		session := makeTestingSession()
		crt, err := writeTestingCerts(t.TempDir())
		if err != nil {
			t.Errorf("error while testing: %v", err)
		}
		cfg, err := newCertConfigFromOptions(&Options{
			CertPath: crt.cert,
			KeyPath:  crt.key,
			CaPath:   crt.ca,
		})
		if err != nil {
			t.Errorf("error while testing: %v", err)
		}

		_, err = initTLS(session, cfg)
		if err != nil {
			t.Errorf("initTLS() error = %v, want: nil", err)
		}
	})

	t.Run("default options from bytes should not fail", func(t *testing.T) {
		session := makeTestingSession()
		cfg, err := newCertConfigFromOptions(&Options{
			Cert: pemTestingCertificate,
			Key:  pemTestingKey,
			Ca:   pemTestingCa,
		})
		if err != nil {
			t.Errorf("error while testing: %v", err)
		}
		_, err = initTLS(session, cfg)
		if err != nil {
			t.Errorf("initTLS() error = %v, want: nil", err)
		}
	})
}

// mock good handshake

type dummyTLSConn struct {
	tls.Conn
}

var _ handshaker = &dummyTLSConn{} // Ensure that we implement handshaker

func (d *dummyTLSConn) Handshake() error {
	return nil
}

func dummyTLSFactory(net.Conn, *tls.Config) (handshaker, error) {
	return &dummyTLSConn{tls.Conn{}}, nil
}

// mock bad handshake

type dummyTLSConnBadHandshake struct {
	tls.Conn
}

var _ handshaker = &dummyTLSConnBadHandshake{} // Ensure that we implement handshaker

func (d *dummyTLSConnBadHandshake) Handshake() error {
	return errors.New("dummy error")
}

func dummyTLSFactoryBadHandshake(net.Conn, *tls.Config) (handshaker, error) {
	return &dummyTLSConnBadHandshake{tls.Conn{}}, nil
}

var tlsFactoryError = errors.New("tlsFactory error")

func errorRaisingTLSFactory(net.Conn, *tls.Config) (handshaker, error) {
	return nil, tlsFactoryError
}

func Test_tlsHandshake(t *testing.T) {

	makeConnAndConf := func() (*controlChannelTLSConn, *tls.Config) {
		conn := &mocks.Conn{}
		s := makeTestingSession()
		r := newReliableTransport(s)
		tc, _ := newControlChannelTLSConn(conn, r)

		conf := &tls.Config{
			InsecureSkipVerify: true,
		}
		return tc, conf
	}

	t.Run("mocked good handshake should not fail", func(t *testing.T) {
		origTLS := tlsFactoryFn
		tlsFactoryFn = dummyTLSFactory
		defer func() {
			tlsFactoryFn = origTLS
		}()

		conn, conf := makeConnAndConf()

		_, err := tlsHandshake(conn, conf)
		if err != nil {
			t.Errorf("tlsHandshake() error = %v, wantErr %v", err, nil)
			return
		}
	})

	t.Run("mocked bad handshake should fail", func(t *testing.T) {
		origTLS := tlsFactoryFn
		tlsFactoryFn = dummyTLSFactoryBadHandshake
		defer func() {
			tlsFactoryFn = origTLS
		}()

		conn, conf := makeConnAndConf()

		wantErr := ErrBadTLSHandshake
		_, err := tlsHandshake(conn, conf)
		if !errors.Is(err, wantErr) {
			t.Errorf("tlsHandshake() error = %v, wantErr %v", err, wantErr)
			return
		}
	})

	t.Run("any error from the factory should be bubbled up", func(t *testing.T) {
		origTLS := tlsFactoryFn
		tlsFactoryFn = errorRaisingTLSFactory
		defer func() {
			tlsFactoryFn = origTLS
		}()
		wantErr := tlsFactoryError

		conn, conf := makeConnAndConf()

		_, err := tlsHandshake(conn, conf)
		if !errors.Is(err, wantErr) {
			t.Errorf("tlsHandshake() error = %v, wantErr %v", err, wantErr)
			return
		}
	})
}

func Test_defaultTLSFactory(t *testing.T) {
	conn := &mocks.Conn{}
	conf := &tls.Config{}
	defaultTLSFactory(conn, conf)
}

func Test_parrotTLSFactory(t *testing.T) {
	conn := &mocks.Conn{}
	conf := &tls.Config{InsecureSkipVerify: true}

	t.Run("parrotTLS factory does not return any error by default", func(t *testing.T) {
		_, err := parrotTLSFactory(conn, conf)
		if err != nil {
			t.Errorf("parrotTLSFactory() error = %v, wantErr %v", err, nil)
			return
		}
	})

	t.Run("an hex clienthello that cannot be decoded to raw bytes should raise ErrBadParrot", func(t *testing.T) {
		defer func(original string) {
			vpnClientHelloHex = original
		}(vpnClientHelloHex)
		vpnClientHelloHex = `aaa`

		_, err := parrotTLSFactory(conn, conf)
		wantErr := ErrBadParrot
		if !errors.Is(err, wantErr) {
			t.Errorf("tlsHandshake() error = %v, wantErr %v", err, wantErr)
			return
		}
	})

	t.Run("an hex representation that is not a valid clienthello should raise ErrBadParrot", func(t *testing.T) {
		defer func(original string) {
			vpnClientHelloHex = original
		}(vpnClientHelloHex)
		vpnClientHelloHex = `deadbeef`

		_, err := parrotTLSFactory(conn, conf)
		wantErr := ErrBadParrot
		if !errors.Is(err, wantErr) {
			t.Errorf("tlsHandshake() error = %v, wantErr %v", err, wantErr)
			return
		}
	})

	// TODO(ainghazal): there's an extra error case that I'm not pretty sure how to reach
	// (error on client.ApplyPreset)
}

func Test_customVerify(t *testing.T) {

	t.Run("happy path: a correct certChain should validate if we pin with the good ca", func(t *testing.T) {
		rawCerts, ca, vpnCert, vpnKey, err := makeRawCertsForTesting()
		if err != nil {
			t.Errorf("error getting raw certs")
			return
		}

		auth, err := makeCertAndCAFromMemory(ca, vpnCert, vpnKey)
		customVerify := customVerifyFactory(auth)

		err = customVerify(rawCerts, nil)
		if err != nil {
			t.Errorf("customVerify() error = %v, wantErr %v", err, nil)
		}
	})

	t.Run("a certChain should not validate if we do not pin the proper ca", func(t *testing.T) {
		rawCerts, _, vpnCert, vpnKey, err := makeRawCertsForTesting()
		if err != nil {
			t.Errorf("error getting raw certs")
			return
		}
		_, badCa, _, _, err := makeRawCertsForTesting()
		if err != nil {
			t.Errorf("error getting raw certs")
			return
		}

		auth, err := makeCertAndCAFromMemory(badCa, vpnCert, vpnKey)
		customVerify := customVerifyFactory(auth)

		wantErr := ErrCannotVerifyCertChain
		err = customVerify(rawCerts, nil)

		if !errors.Is(err, wantErr) {
			t.Errorf("customVerify() error = %v, wantErr %v", err, nil)
		}
	})

	t.Run("a certChain should not validate if we pass an empty ca", func(t *testing.T) {
		rawCerts, _, vpnCert, vpnKey, err := makeRawCertsForTesting()
		if err != nil {
			t.Errorf("error getting raw certs")
			return
		}

		emptyCa := &x509.Certificate{}

		auth, err := makeCertAndCAFromMemory(emptyCa, vpnCert, vpnKey)
		customVerify := customVerifyFactory(auth)

		wantErr := ErrCannotVerifyCertChain
		err = customVerify(rawCerts, nil)

		if !errors.Is(err, wantErr) {
			t.Errorf("customVerify() error = %v, wantErr %v", err, nil)
		}
	})

	t.Run("a correct certChain fails if DNSName is set in VerifyOptions", func(t *testing.T) {
		// this test is really only testing the behavior of golang x509 validation
		// in the stdlib, but it gives me more faith in the correctness
		// of the custom verify function
		rawCerts, ca, vpnCert, vpnKey, err := makeRawCertsForTesting()
		if err != nil {
			t.Errorf("error getting raw certs")
			return
		}

		defer func(orig func() x509.VerifyOptions) {
			certVerifyOptions = orig
		}(certVerifyOptions)

		// the test cert has random.gateway set as the DNSName, so we're just verifying
		// that the verification actually fails with options different from the default that we're
		// setting in the certVerifyOptions global.
		certVerifyOptions = func() x509.VerifyOptions {
			return x509.VerifyOptions{DNSName: "other.gateway"}
		}

		wantErr := ErrCannotVerifyCertChain

		auth, err := makeCertAndCAFromMemory(ca, vpnCert, vpnKey)
		customVerify := customVerifyFactory(auth)

		err = customVerify(rawCerts, nil)
		if !errors.Is(err, wantErr) {
			t.Errorf("customVerify() error = %v, wantErr %v", err, nil)
		}
	})

	t.Run("empty certchain raises error", func(t *testing.T) {
		emptyCerts := [][]byte{[]byte{}, []byte{}}
		wantErr := ErrCannotVerifyCertChain

		_, ca, vpnCert, vpnKey, err := makeRawCertsForTesting()
		if err != nil {
			t.Errorf("error getting raw certs")
			return
		}

		auth, err := makeCertAndCAFromMemory(ca, vpnCert, vpnKey)
		customVerify := customVerifyFactory(auth)

		err = customVerify(emptyCerts, nil)
		if !errors.Is(err, wantErr) {
			t.Errorf("customVerify() error = %v, wantErr %v", err, wantErr)
		}
	})

	t.Run("garbage certchain raises error", func(t *testing.T) {
		garbageCerts := [][]byte{[]byte{0xde, 0xad}, []byte{0xbe, 0xef}}
		wantErr := ErrCannotVerifyCertChain

		_, ca, vpnCert, vpnKey, err := makeRawCertsForTesting()
		if err != nil {
			t.Errorf("error getting raw certs")
			return
		}

		auth, err := makeCertAndCAFromMemory(ca, vpnCert, vpnKey)
		customVerify := customVerifyFactory(auth)

		err = customVerify(garbageCerts, nil)
		if !errors.Is(err, wantErr) {
			t.Errorf("customVerify() error = %v, wantErr %v", err, wantErr)
		}
	})

	t.Run("attempting to verify one cert with a different ca raises error", func(t *testing.T) {
		certChainOne, _, _, _, _ := makeRawCertsForTesting()
		certChainTwo, _, _, _, _ := makeRawCertsForTesting()
		badChain := [][]byte{certChainOne[0], certChainTwo[1]}
		wantErr := ErrCannotVerifyCertChain

		_, ca, vpnCert, vpnKey, err := makeRawCertsForTesting()
		if err != nil {
			t.Errorf("error getting raw certs")
			return
		}

		auth, err := makeCertAndCAFromMemory(ca, vpnCert, vpnKey)
		customVerify := customVerifyFactory(auth)

		err = customVerify(badChain, nil)
		if !errors.Is(err, wantErr) {
			t.Errorf("customVerify() error = %v, wantErr %v", err, wantErr)
		}
	})
}

// makeRawCertsForTesting creates a CA, and returns:
// * an array of byte arrays containing a cert signed with that CA and the CA itself (to be used to test the verify routine).
// * the ca used to sign the certs
// * a cert that simulates a vpn certificate signed by the ca (rsa)
// * the private key for the vpn certificate
// * an error if it could not build any of the certs correctly.
func makeRawCertsForTesting() ([][]byte, *x509.Certificate, []byte, []byte, error) {
	// set up a CA certificate. this sets up a 2048 cert for the ca, if we ever
	// want to shave milliseconds we can roll a ca with a smaller key size.
	ca, caPrivKey, err := mitm.NewAuthority("ca", "oonitarians united", 1*time.Hour)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// set up a leaf certificate - this would be the gateway cert
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1984),
		Subject: pkix.Name{
			Organization:  []string{"Oonitarians united"},
			StreetAddress: []string{"On a pinneaple at the bottom of the sea"},
			CommonName:    "random.gateway",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		DNSNames:  []string{"random.gateway", "randomgw"},
	}

	// tiny cert size to make tests go brrr
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// set up a vpn certificate - this would be the client cert
	vpnCert := &x509.Certificate{
		SerialNumber: big.NewInt(1984),
		Subject: pkix.Name{
			Organization:  []string{"Oonitarians united"},
			StreetAddress: []string{"On a pinneaple at the bottom of the sea"},
			CommonName:    "client cert",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
	}

	// tiny cert size to make tests go brrr
	vpnCertPrivKey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	vpnCertBytes, err := x509.CreateCertificate(rand.Reader, vpnCert, ca, &vpnCertPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	vpnKeyBytes := x509.MarshalPKCS1PrivateKey(vpnCertPrivKey)

	result := [][]byte{certBytes, caBytes}
	return result, ca, vpnCertBytes, vpnKeyBytes, nil
}

func makeCertAndCAFromMemory(caCert *x509.Certificate, vpnCert []byte, vpnKey []byte) (*certConfig, error) {
	ca := x509.NewCertPool()
	ca.AddCert(caCert)
	cert, _ := tls.X509KeyPair(vpnCert, vpnKey)
	auth := &certConfig{
		ca:   ca,
		cert: cert,
	}
	return auth, nil
}
