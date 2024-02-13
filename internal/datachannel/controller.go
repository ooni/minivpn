package datachannel

import (
	"bytes"
	"crypto/hmac"
	"fmt"
	"strings"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/bytesx"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/runtimex"
	"github.com/ooni/minivpn/internal/session"
)

// dataChannelHandler manages the data "channel".
type dataChannelHandler interface {
	setupKeys(*session.DataChannelKey) error
	writePacket([]byte) (*model.Packet, error)
	readPacket(*model.Packet) ([]byte, error)
	decodeEncryptedPayload([]byte, *dataChannelState) (*encryptedData, error)
	encryptAndEncodePayload([]byte, *dataChannelState) ([]byte, error)
}

// DataChannel represents the data "channel", that will encrypt and decrypt the tunnel payloads.
// data implements the dataHandler interface.
type DataChannel struct {
	options         *model.OpenVPNOptions
	sessionManager  *session.Manager
	state           *dataChannelState
	decodeFn        func(model.Logger, []byte, *session.Manager, *dataChannelState) (*encryptedData, error)
	encryptEncodeFn func(model.Logger, []byte, *session.Manager, *dataChannelState) ([]byte, error)
	decryptFn       func([]byte, *encryptedData) ([]byte, error)
	log             model.Logger
}

var _ dataChannelHandler = &DataChannel{} // Ensure that we implement dataChannelHandler

// NewDataChannelFromOptions returns a new data object, initialized with the
// options given. it also returns any error raised.
func NewDataChannelFromOptions(log model.Logger,
	opt *model.OpenVPNOptions,
	sessionManager *session.Manager) (*DataChannel, error) {
	runtimex.Assert(opt != nil, "openvpn datachannel: opts cannot be nil")
	runtimex.Assert(opt != nil, "openvpn datachannel: opts cannot be nil")
	runtimex.Assert(len(opt.Cipher) != 0, "need a configured cipher option")
	runtimex.Assert(len(opt.Auth) != 0, "need a configured auth option")

	state := &dataChannelState{}
	data := &DataChannel{
		options:        opt,
		sessionManager: sessionManager,
		state:          state,
	}

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
		return data, fmt.Errorf("%w: %s", errDataChannel, fmt.Sprintf("no such mac: %v", opt.Auth))
	}
	data.state.hash = hmacHash
	data.decryptFn = state.dataCipher.decrypt

	log.Info(fmt.Sprintf("Cipher: %s", opt.Cipher))
	log.Info(fmt.Sprintf("Auth:   %s", opt.Auth))

	return data, nil
}

// DecodeEncryptedPayload calls the corresponding function for AEAD or Non-AEAD decryption.
func (d *DataChannel) decodeEncryptedPayload(b []byte, dcs *dataChannelState) (*encryptedData, error) {
	return d.decodeFn(d.log, b, d.sessionManager, dcs)
}

// setSetupKeys performs the key expansion from the local and remote
// keySources, initializing the data channel state.
func (d *DataChannel) setupKeys(dck *session.DataChannelKey) error {
	runtimex.Assert(dck != nil, "data channel key cannot be nil")
	if !dck.Ready() {
		return fmt.Errorf("%w: %s", errDataChannelKey, "key not ready")
	}
	master := prf(
		dck.Local().PreMaster[:],
		[]byte("OpenVPN master secret"),
		dck.Local().R1[:],
		dck.Remote().R1[:],
		[]byte{}, []byte{},
		48)

	keys := prf(
		master,
		[]byte("OpenVPN key expansion"),
		dck.Local().R2[:],
		dck.Remote().R2[:],
		d.sessionManager.LocalSessionID(),
		d.sessionManager.RemoteSessionID(),
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

func (d *DataChannel) writePacket(payload []byte) (*model.Packet, error) {
	runtimex.Assert(d.state != nil, "data: nil state")
	runtimex.Assert(d.state.dataCipher != nil, "data.state: nil dataCipher")

	var plain []byte
	var err error

	switch d.state.dataCipher.isAEAD() {
	case true:
		plain, err = doCompress(payload, d.options.Compress)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrCannotEncrypt, err)
		}
	case false: // non-aead
		localPacketID, _ := d.sessionManager.LocalDataPacketID()
		plain = prependPacketID(localPacketID, payload)

		plain, err = doCompress(plain, d.options.Compress)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrCannotEncrypt, err)
		}
	}

	// encrypted adds padding, if needed, and it also includes the
	// opcode/keyid and peer-id headers and, if used, any authenticated
	// parts in the packet.
	encrypted, err := d.encryptAndEncodePayload(plain, d.state)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrCannotEncrypt, err)
	}

	// TODO(ainghazal): increment counter for used bytes?
	// and trigger renegotiation if we're near the end of the key useful lifetime.

	packet := model.NewPacket(model.P_DATA_V2, d.sessionManager.CurrentKeyID(), encrypted)
	peerid := &bytes.Buffer{}
	bytesx.WriteUint24(peerid, uint32(d.sessionManager.TunnelInfo().PeerID))
	packet.PeerID = model.PeerID(peerid.Bytes())
	return packet, nil
}

// encrypt calls the corresponding function for AEAD or Non-AEAD decryption.
// Due to the particularities of the iv generation on each of the modes, encryption and encoding are
// done together in the same function.
func (d *DataChannel) encryptAndEncodePayload(plaintext []byte, dcs *dataChannelState) ([]byte, error) {
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

	encrypted, err := d.encryptEncodeFn(d.log, padded, d.sessionManager, d.state)
	if err != nil {
		return nil,
			fmt.Errorf("%w: %s", ErrCannotEncrypt, err)
	}
	return encrypted, nil

}

//
// read + decrypt
//

func (d *DataChannel) readPacket(p *model.Packet) ([]byte, error) {
	if len(p.Payload) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrCannotDecrypt, "empty payload")
	}
	runtimex.Assert(p.IsData(), "ReadPacket expects data packet")

	plaintext, err := d.decrypt(p.Payload)
	if err != nil {
		return nil, err
	}

	// get plaintext payload from the decrypted plaintext
	return maybeDecompress(plaintext, d.state, d.options)
}

func (d *DataChannel) decrypt(encrypted []byte) ([]byte, error) {
	if d.decryptFn == nil {
		return []byte{}, errInitError
	}
	if len(d.state.hmacKeyRemote) == 0 {
		d.log.Warn("decrypt: not ready yet")
		return nil, ErrCannotDecrypt
	}
	encryptedData, err := d.decodeEncryptedPayload(encrypted, d.state)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrCannotDecrypt, err)
	}

	plainText, err := d.decryptFn(d.state.cipherKeyRemote[:], encryptedData)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrCannotDecrypt, err)
	}
	return plainText, nil
}
