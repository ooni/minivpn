package datachannel

import (
	"crypto/hmac"
	"fmt"
	"strings"
)

// data represents the data "channel", that will encrypt and decrypt the tunnel payloads.
// data implements the dataHandler interface.
type data struct {
	options         *options.Options
	session         *session
	state           *dataChannelState
	decodeFn        func([]byte, *dataChannelState) (*encryptedData, error)
	encryptEncodeFn func([]byte, *session, *dataChannelState) ([]byte, error)
	decryptFn       func([]byte, *encryptedData) ([]byte, error)
}

var _ dataHandler = &data{} // Ensure that we implement dataHandler

// NewDataFromOptions returns a new data object, initialized with the
// options given. it also returns any error raised.
func NewDataFromOptions(opt *Options, s *session) (*data, error) {
	if opt == nil || s == nil {
		return nil, fmt.Errorf("%w: %s", errBadInput, "found nil on init")
	}
	if len(opt.Cipher) == 0 || len(opt.Auth) == 0 {
		return nil, fmt.Errorf("%w: %s", errBadInput, "empty options")
	}
	state := &dataChannelState{}
	data := &data{options: opt, session: s, state: state}

	logger.Info(fmt.Sprintf("Cipher: %s", opt.Cipher))

	dataCipher, err := newDataCipherFromCipherSuite(opt.Cipher)
	if err != nil {
		return data, err
	}
	data.state.dataCipher = dataCipher
	switch dataCipher.isAEAD() {
	case true:
		data.decodeFn = decodeEncryptedPayloadAEAD
		data.encryptEncodeFn = encryptAndEncodePayloadAEAD
	case false:
		data.decodeFn = decodeEncryptedPayloadNonAEAD
		data.encryptEncodeFn = encryptAndEncodePayloadNonAEAD
	}

	logger.Info(fmt.Sprintf("Auth:   %s", opt.Auth))

	hmacHash, ok := newHMACFactory(strings.ToLower(opt.Auth))
	if !ok {
		return data, fmt.Errorf("%w:%s", errBadInput, "no such mac")
	}
	data.state.hash = hmacHash
	data.decryptFn = state.dataCipher.decrypt

	return data, nil
}

// DecodeEncryptedPayload calls the corresponding function for AEAD or Non-AEAD decryption.
func (d *data) DecodeEncryptedPayload(b []byte, dcs *dataChannelState) (*encryptedData, error) {
	return d.decodeFn(b, dcs)
}

// SetSetupKeys performs the key expansion from the local and remote
// keySources, initializing the data channel state.
func (d *data) SetupKeys(dck *dataChannelKey) error {
	if dck == nil {
		return fmt.Errorf("%w: %s", errBadInput, "nil args")
	}
	if !dck.ready {
		return fmt.Errorf("%w: %s", errDataChannelKey, "key not ready")
	}
	master := prf(
		dck.local.preMaster[:],
		[]byte("OpenVPN master secret"),
		dck.local.r1[:],
		dck.remote.r1[:],
		[]byte{}, []byte{},
		48)

	keys := prf(
		master,
		[]byte("OpenVPN key expansion"),
		dck.local.r2[:],
		dck.remote.r2[:],
		d.session.LocalSessionID[:], d.session.RemoteSessionID[:],
		256)

	var keyLocal, hmacLocal, keyRemote, hmacRemote keySlot
	copy(keyLocal[:], keys[0:64])
	copy(hmacLocal[:], keys[64:128])
	copy(keyRemote[:], keys[128:192])
	copy(hmacRemote[:], keys[192:256])

	d.state.cipherKeyLocal = keyLocal
	d.state.hmacKeyLocal = hmacLocal
	d.state.cipherKeyRemote = keyRemote
	d.state.hmacKeyRemote = hmacRemote

	logger.Debugf("Cipher key local:  %x", keyLocal)
	logger.Debugf("Cipher key remote: %x", keyRemote)
	logger.Debugf("Hmac key local:    %x", hmacLocal)
	logger.Debugf("Hmac key remote:   %x", hmacRemote)

	hashSize := d.state.hash().Size()
	d.state.hmacLocal = hmac.New(d.state.hash, hmacLocal[:hashSize])
	d.state.hmacRemote = hmac.New(d.state.hash, hmacRemote[:hashSize])

	logger.Info("Key derivation OK")
	return nil
}

// SetPeerID updates the data state field with the info sent by the server.
func (d *data) SetPeerID(i int) error {
	d.state.peerID = i
	return nil
}
