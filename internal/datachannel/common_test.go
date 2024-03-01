package datachannel

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"testing"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/runtimex"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/vpntest"
)

func makeTestingSession() *session.Manager {
	manager, err := session.NewManager(model.NewConfig())
	runtimex.PanicOnError(err, "could not get session manager")
	manager.SetRemoteSessionID(model.SessionID{0x01})
	return manager
}

func makeTestingOptions(t *testing.T, cipher, auth string) *model.OpenVPNOptions {
	crt, _ := vpntest.WriteTestingCerts(t.TempDir())
	opt := &model.OpenVPNOptions{
		Cipher:   cipher,
		Auth:     auth,
		CertPath: crt.Cert,
		KeyPath:  crt.Key,
		CAPath:   crt.CA,
	}
	return opt
}

func makeTestingStateAEAD() *dataChannelState {
	dataCipher, _ := newDataCipher(cipherNameAES, 128, cipherModeGCM)
	st := &dataChannelState{
		hash:            sha1.New,
		cipherKeyLocal:  *(*keySlot)(bytes.Repeat([]byte{0x65}, 64)),
		cipherKeyRemote: *(*keySlot)(bytes.Repeat([]byte{0x66}, 64)),
		hmacKeyLocal:    *(*keySlot)(bytes.Repeat([]byte{0x67}, 64)),
		hmacKeyRemote:   *(*keySlot)(bytes.Repeat([]byte{0x68}, 64)),
	}
	st.hmacLocal = hmac.New(st.hash, st.hmacKeyLocal[:20])
	st.hmacRemote = hmac.New(st.hash, st.hmacKeyRemote[:20])
	st.dataCipher = dataCipher
	return st
}

func makeTestingStateNonAEAD() *dataChannelState {
	dataCipher, _ := newDataCipher(cipherNameAES, 128, cipherModeCBC)
	st := &dataChannelState{
		hash:            sha1.New,
		cipherKeyLocal:  *(*keySlot)(bytes.Repeat([]byte{0x65}, 64)),
		cipherKeyRemote: *(*keySlot)(bytes.Repeat([]byte{0x66}, 64)),
		hmacKeyLocal:    *(*keySlot)(bytes.Repeat([]byte{0x67}, 64)),
		hmacKeyRemote:   *(*keySlot)(bytes.Repeat([]byte{0x68}, 64)),
	}
	st.hmacLocal = hmac.New(st.hash, st.hmacKeyLocal[:20])
	st.hmacRemote = hmac.New(st.hash, st.hmacKeyRemote[:20])
	st.dataCipher = dataCipher
	return st
}

func makeTestingStateNonAEADReversed() *dataChannelState {
	dataCipher, _ := newDataCipher(cipherNameAES, 128, cipherModeCBC)
	st := &dataChannelState{
		hash:            sha1.New,
		cipherKeyRemote: *(*keySlot)(bytes.Repeat([]byte{0x65}, 64)),
		cipherKeyLocal:  *(*keySlot)(bytes.Repeat([]byte{0x66}, 64)),
		hmacKeyRemote:   *(*keySlot)(bytes.Repeat([]byte{0x67}, 64)),
		hmacKeyLocal:    *(*keySlot)(bytes.Repeat([]byte{0x68}, 64)),
	}
	st.hmacLocal = hmac.New(st.hash, st.hmacKeyLocal[:20])
	st.hmacRemote = hmac.New(st.hash, st.hmacKeyRemote[:20])
	st.dataCipher = dataCipher
	return st
}

const (
	rnd16 = "0123456789012345"
	rnd32 = "01234567890123456789012345678901"
	rnd48 = "012345678901234567890123456789012345678901234567"
)

func makeTestKeys() ([32]byte, [32]byte, [48]byte) {
	r1 := *(*[32]byte)([]byte(rnd32))
	r2 := *(*[32]byte)([]byte(rnd32))
	r3 := *(*[48]byte)([]byte(rnd48))
	return r1, r2, r3
}

func makeTestingDataChannelKey() *session.DataChannelKey {
	rl1, rl2, preml := makeTestKeys()
	rr1, rr2, premr := makeTestKeys()

	ksLocal := &session.KeySource{R1: rl1, R2: rl2, PreMaster: preml}
	ksRemote := &session.KeySource{R1: rr1, R2: rr2, PreMaster: premr}

	dck := &session.DataChannelKey{}
	dck.AddLocalKey(ksLocal)
	dck.AddRemoteKey(ksRemote)
	return dck
}
