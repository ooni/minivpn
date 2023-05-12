package datachannel

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/runtimex"
	"github.com/ooni/minivpn/internal/session"
)

var (
	errDataChannel = errors.New("datachannel error")
)

// dataChannelHandler manages the data "channel".
type dataChannelHandler interface {
	setupKeys(*dataChannelKey) error
	setPeerID(int) error
	writePacket(net.Conn, []byte) (int, error)
	readPacket(*model.Packet) ([]byte, error)
	decodeEncryptedPayload([]byte, *dataChannelState) (*encryptedData, error)
	encryptAndEncodePayload([]byte, *dataChannelState) ([]byte, error)
}

// dataChannel represents the data "channel", that will encrypt and decrypt the tunnel payloads.
// data implements the dataHandler interface.
type dataChannel struct {
	options         *options.Options
	session         *session.Session
	state           *dataChannelState
	decodeFn        func([]byte, *dataChannelState) (*encryptedData, error)
	encryptEncodeFn func([]byte, *session.Session, *dataChannelState) ([]byte, error)
	decryptFn       func([]byte, *encryptedData) ([]byte, error)
	log             log.Logger
}

var _ dataChannelHandler = &dataChannel{} // Ensure that we implement dataChannelHandler

// NewDataChannelFromOptions returns a new data object, initialized with the
// options given. it also returns any error raised.
func NewDataChannelFromOptions(log model.Logger, opt *options.Options, sess *session.Session) (*dataChannel, error) {
	runtimex.Assert(opt != nil, "openvpn datachannel: opts cannot be nil")
	runtimex.Assert(opt != nil, "openvpn datachannel: opts cannot be nil")
	runtimex.Assert(len(opt.Cipher) != 0, "need a configured cipher option")
	runtimex.Assert(len(opt.Auth) != 0, "need a configured auth option")

	state := &dataChannelState{}
	data := &dataChannel{options: opt, session: sess, state: state}

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

	hmacHash, ok := newHMACFactory(strings.ToLower(opt.Auth))
	if !ok {
		return data, fmt.Errorf("%w: %s", errDataChannel, "no such mac: %v", opt.Auth)
	}
	data.state.hash = hmacHash
	data.decryptFn = state.dataCipher.decrypt

	log.Info(fmt.Sprintf("Cipher: %s", opt.Cipher))
	log.Info(fmt.Sprintf("Auth:   %s", opt.Auth))

	return data, nil
}

// DecodeEncryptedPayload calls the corresponding function for AEAD or Non-AEAD decryption.
func (d *dataChannel) decodeEncryptedPayload(b []byte, dcs *dataChannelState) (*encryptedData, error) {
	return d.decodeFn(b, dcs)
}

// SetSetupKeys performs the key expansion from the local and remote
// keySources, initializing the data channel state.
func (d *dataChannel) setupKeys(dck *dataChannelKey) error {
	runtimex.Assert(dck != nil, "data channel key cannot be nil")
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
		// TODO(ainghazal): use accessors here
		d.session.LocalSessionID[:],
		d.session.RemoteSessionID[:],
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

	log.Debugf("Cipher key local:  %x", keyLocal)
	log.Debugf("Cipher key remote: %x", keyRemote)
	log.Debugf("Hmac key local:    %x", hmacLocal)
	log.Debugf("Hmac key remote:   %x", hmacRemote)

	hashSize := d.state.hash().Size()
	d.state.hmacLocal = hmac.New(d.state.hash, hmacLocal[:hashSize])
	d.state.hmacRemote = hmac.New(d.state.hash, hmacRemote[:hashSize])

	log.Info("Key derivation OK")
	return nil
}

//
// write + encrypt
//

func (d *dataChannel) writePacket(conn net.Conn, payload []byte) (int, error) {
	runtimex.Assert(d.state != nil, "data: nil state")
	runtimex.Assert(d.state.dataCipher != nil, "data.state: nil dataCipher")

	var plain []byte
	var err error

	switch d.state.dataCipher.isAEAD() {
	case true:
		plain, err = doCompress(payload, d.options.Compress)
		if err != nil {
			return 0, fmt.Errorf("%w: %s", ErrCannotEncrypt, err)
		}
	case false: // non-aead
		localPacketID, _ := d.session.LocalPacketID()
		plain = prependPacketID(localPacketID, payload)

		plain, err = doCompress(plain, d.options.Compress)
		if err != nil {
			return 0, fmt.Errorf("%w: %s", ErrCannotEncrypt, err)
		}
	}

	// encrypted adds padding, if needed, and it also includes the
	// opcode/keyid and peer-id headers and, if used, any authenticated
	// parts in the packet.
	encrypted, err := d.encryptAndEncodePayload(plain, d.state)
	if err != nil {
		return 0, fmt.Errorf("%w: %s", ErrCannotEncrypt, err)
	}
	_ = encrypted

	// TODO(ainghazal): increment counter for used bytes?
	// and trigger renegotiation if we're near the end of the key useful lifetime.

	// TODO: return encrypted to be written down...
	// out := maybeAddSizeFrame(conn, encrypted)
	return 0, nil

}

// encrypt calls the corresponding function for AEAD or Non-AEAD decryption.
// Due to the particularities of the iv generation on each of the modes, encryption and encoding are
// done together in the same function.
// TODO accept state for symmetry
func (d *dataChannel) encryptAndEncodePayload(plaintext []byte, dcs *dataChannelState) ([]byte, error) {
	runtimex.Assert(dcs != nil, "datachanelState is nil")
	runtimex.Assert(dcs.dataCipher != nil, "dcs.dataCipher is nil")

	if len(plaintext) == 0 {
		return nil, fmt.Errorf("%w: nothing to encrypt", ErrCannotEncrypt)
	}

	padded, err := doPadding(plaintext, d.options.Compress, dcs.dataCipher.blockSize())
	if err != nil {
		return nil,
			fmt.Errorf("%w: %s", ErrCannotEncrypt, err)
	}

	encrypted, err := d.encryptEncodeFn(padded, d.session, d.state)
	if err != nil {
		return nil,
			fmt.Errorf("%w: %s", ErrCannotEncrypt, err)
	}
	return encrypted, nil

}

//
// read + decrypt
//

func (d *dataChannel) readPacket(p *model.Packet) ([]byte, error) {
	if len(p.Payload) == 0 {
		return []byte{}, fmt.Errorf("%w: %s", ErrCannotDecrypt, "empty payload")
	}
	runtimex.Assert(p.IsData(), "ReadPacket expects data packet")

	plaintext, err := d.decrypt(p.Payload)
	if err != nil {
		return []byte{}, err
	}

	// get plaintext payload from the decrypted plaintext
	return maybeDecompress(plaintext, d.state, d.options)
}

func (d *dataChannel) decrypt(encrypted []byte) ([]byte, error) {
	if d.decryptFn == nil {
		return []byte{}, errInitError
	}
	if len(d.state.hmacKeyRemote) == 0 {
		d.log.Error("decrypt: not ready yet")
		return []byte{}, ErrCannotDecrypt
	}
	encryptedData, err := d.decodeEncryptedPayload(encrypted, d.state)

	if err != nil {
		return []byte{}, fmt.Errorf("%w: %s", ErrCannotDecrypt, err)
	}
	plainText, err := d.decryptFn(d.state.cipherKeyRemote[:], encryptedData)
	if err != nil {
		return []byte{}, fmt.Errorf("%w: %s", ErrCannotDecrypt, err)
	}
	return plainText, nil
}

// SetPeerID updates the data state field with the info sent by the server.
func (d *dataChannel) setPeerID(i int) error {
	d.state.peerID = i
	return nil
}
