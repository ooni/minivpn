package vpntest

import "os"

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

// TestingCert holds key, cert and ca to pass to tests needing to mock certificates.
type TestingCert struct {
	Cert string
	Key  string
	CA   string
}

// WriteTEestingCerts will write valid certificates in the passed dir, and return a [TestingCert] and any error.
func WriteTestingCerts(dir string) (TestingCert, error) {
	certFile, err := os.CreateTemp(dir, "tmpfile-")
	if err != nil {
		return TestingCert{}, err
	}
	certFile.Write(pemTestingCertificate)

	keyFile, err := os.CreateTemp(dir, "tmpfile-")
	if err != nil {
		return TestingCert{}, err
	}
	keyFile.Write(pemTestingKey)

	caFile, err := os.CreateTemp(dir, "tmpfile-")
	if err != nil {
		return TestingCert{}, err
	}
	caFile.Write(pemTestingCa)

	testingCert := TestingCert{
		Cert: certFile.Name(),
		Key:  keyFile.Name(),
		CA:   caFile.Name(),
	}
	return testingCert, nil
}