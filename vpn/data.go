package vpn

//
// OpenVPN data channel
//

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net"
	"strings"
	"sync"
)

var (
	errDataChannelKey = errors.New("bad key")
	errBadCompression = errors.New("bad compression")
	errReplayAttack   = errors.New("replay attack")
	errCannotEncrypt  = errors.New("cannot encrypt")
	errCannotDecrypt  = errors.New("cannot decrypt")
	errBadHMAC        = errors.New("bad hmac")
)

// keySlot holds the different local and remote keys.
type keySlot [64]byte

// dataChannelState is the state of the data channel.
type dataChannelState struct {
	dataCipher dataCipher
	hmac       func() hash.Hash
	// TODO use Hash.Size() instead
	hmacSize        int
	remotePacketID  packetID
	cipherKeyLocal  keySlot
	cipherKeyRemote keySlot
	hmacKeyLocal    keySlot
	hmacKeyRemote   keySlot

	mu sync.Mutex
}

// SetSetRemotePacketID stores the passed packetID internally.
func (dcs *dataChannelState) SetRemotePacketID(id packetID) bool {
	dcs.mu.Lock()
	defer dcs.mu.Unlock()
	dcs.remotePacketID = packetID(id)
	return true
}

// RemotePacketID returns the last known remote packetID.
func (dcs *dataChannelState) RemotePacketID() packetID {
	dcs.mu.Lock()
	defer dcs.mu.Unlock()
	return dcs.remotePacketID
}

// dataChannelKey represents a pair of key sources that have been negotiated
// over the control channel, and from which we will derive local and remote
// keys for encryption and decrption over the data channel. The index refers to
// the short key_id that is passed in the lower 3 bits if a packet header.
// The setup of the keys for a given data channel (that is, for every key_id)
// is made by expanding the keysources using the prf function.
// Do note that we are not yet implementing key renegotiation - but the index
// is provided for convenience when/if we support that in the future.
type dataChannelKey struct {
	index  uint32
	ready  bool
	local  *keySource
	remote *keySource
	mu     sync.Mutex
}

// addRemoteKey adds the server keySource to our dataChannelKey. This makes the
// dataChannelKey ready to be used.
func (dck *dataChannelKey) addRemoteKey(k *keySource) error {
	dck.mu.Lock()
	defer dck.mu.Unlock()
	if dck.ready {
		return fmt.Errorf("%w:%s", errDataChannelKey, "cannot overwrite remote key slot")
	}
	dck.remote = k
	dck.ready = true
	return nil
}

var (
	randomFn       = genRandomBytes
	errRandomBytes = errors.New("Error generating random bytes")
)

// random data to generate keys
type keySource struct {
	r1        []byte
	r2        []byte
	preMaster []byte
}

// Bytes returns the byte representation of a keySource
func (k *keySource) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.Write(k.preMaster)
	buf.Write(k.r1)
	buf.Write(k.r2)
	return buf.Bytes()
}

// newKeySource returns a keySource and an error.
func newKeySource() (*keySource, error) {
	r1, err := randomFn(32)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errRandomBytes, err.Error())
	}
	r2, err := randomFn(32)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errRandomBytes, err.Error())
	}
	preMaster, err := randomFn(48)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errRandomBytes, err.Error())
	}
	return &keySource{
		r1:        r1,
		r2:        r2,
		preMaster: preMaster,
	}, nil
}

// data represents the data "channel", that will encrypt and decrypt the tunnel payloads.
// data implements the dataHandler interface.
type data struct {
	options  *Options
	session  *session
	state    *dataChannelState
	decodeFn func([]byte, *dataChannelState) (*encryptedData, error)
}

var _ dataHandler = &data{} // Ensure that we implement controlHandler

// newDataFromOptions returns a new data object, initialized with the
// options given. it also returns any error raised.
func newDataFromOptions(opt *Options, s *session) (*data, error) {
	state := &dataChannelState{}
	data := &data{options: opt, session: s, state: state}

	logger.Info(fmt.Sprintf("Cipher: %s", opt.Cipher))

	dataCipher, err := newDataCipherFromCipherSuite(opt.Cipher)
	if err != nil {
		return data, err
	}
	data.state.dataCipher = dataCipher
	switch dataCipher.cipherMode() {
	case cipherModeGCM:
		data.decodeFn = decodeEncryptedPayloadAEAD
	default:
		data.decodeFn = decodeEncryptedPayloadNonAEAD
	}

	logger.Info(fmt.Sprintf("Auth:   %s", opt.Auth))

	hmac, ok := newHMACFactory(strings.ToLower(opt.Auth))
	if !ok {
		return data, fmt.Errorf("%w:%s", errBadInput, "no such mac")
	}
	data.state.hmac = hmac
	data.state.hmacSize = getHashLength(strings.ToLower(opt.Auth))
	return data, nil
}

// DecodeEncryptedPayload calls the corresponding function for AEAD or Non-AEAD decryption.
func (d *data) DecodeEncryptedPayload(b []byte, dcs *dataChannelState) (*encryptedData, error) {
	fn := d.decodeFn
	return fn(b, dcs)
}

// SetSetupKeys performs the key expansion from the local and remote
// keySources, initializing the data channel state.
func (d *data) SetupKeys(dck *dataChannelKey, s *session) error {
	if !dck.ready {
		return fmt.Errorf("%w: %s", errDataChannelKey, "key not ready")

	}
	master := prf(
		dck.local.preMaster,
		[]byte("OpenVPN master secret"),
		dck.local.r1,
		dck.remote.r1,
		[]byte{}, []byte{},
		48)

	keys := prf(
		master,
		[]byte("OpenVPN key expansion"),
		dck.local.r2,
		dck.remote.r2,
		s.LocalSessionID.Bytes(), s.RemoteSessionID.Bytes(),
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

	logger.Info("Key derivation OK")
	return nil
}

//
// write + encrypt
//

func (d *data) encrypt(plaintext []byte) ([]byte, error) {
	blockSize := d.state.dataCipher.blockSize()
	padded, err := maybeAddCompressPadding(plaintext, d.options, blockSize)
	if err != nil {
		return []byte{}, fmt.Errorf("%w:%s", errCannotEncrypt, err)
	}

	if d.state.dataCipher.isAEAD() {
		packetID := make([]byte, 4)
		localPacketID, _ := d.session.LocalPacketID()
		binary.BigEndian.PutUint32(packetID, uint32(localPacketID))
		iv := append(packetID, d.state.hmacKeyLocal[:8]...)

		ct, err := d.state.dataCipher.encrypt(d.state.cipherKeyLocal[:], iv, padded, packetID)
		if err != nil {
			return []byte{}, fmt.Errorf("%w:%s", errCannotEncrypt, err)
		}

		// openvpn uses tag | payload
		tag := ct[len(ct)-16:]
		payload := ct[:len(ct)-16]

		p := append(packetID, tag...)
		p = append(p, payload...)
		return p, nil
	}

	// non-aead (i.e., CBC encryption):
	// For iv generation, OpenVPN uses a nonce-based PRNG that is initially seeded with
	// OpenSSL RAND_bytes function. I guess this is good enough for our purposes, for now
	iv, err := genRandomBytes(blockSize)
	if err != nil {
		return []byte{}, err
	}
	ciphertext, err := d.state.dataCipher.encrypt(d.state.cipherKeyLocal[:], iv, padded, []byte(""))
	if err != nil {
		return []byte{}, err
	}

	hashLength := getHashLength(strings.ToLower(d.options.Auth))
	key := d.state.hmacKeyLocal[:hashLength]
	mac := hmac.New(d.state.hmac, key)
	mac.Write(append(iv, ciphertext...))
	calcMAC := mac.Sum(nil)

	payload := append(calcMAC, iv...)
	payload = append(payload, ciphertext...)
	return payload, nil
}

// maybeAddCompressPadding does pkcs7 padding of the encryption payloads as
// needed. in the case of AEAD mode, it swaps the first and last byte after
// padding too, according to the spec.
func maybeAddCompressPadding(b []byte, opt *Options, blockSize int) ([]byte, error) {
	if opt.Compress == "stub" {
		// for the compression stub, we need to send the first byte to
		// the last one, after padding
		endByte := b[len(b)-1]
		padded, err := bytesPadPKCS7(b[:len(b)-1], blockSize)
		if err != nil {
			return nil, err
		}
		padded[len(padded)-1] = endByte
		return padded, nil
	}
	padded, err := bytesPadPKCS7(b, blockSize)
	if err != nil {
		return nil, err
	}
	return padded, nil
}

// maybeAddCompressStub adds compression bytes if needed by the passed compression options.
func maybeAddCompressStub(b []byte, opt *Options) []byte {
	if opt.Compress == "stub" {
		// compresssion stub
		b = append(b, b[0])
		b[0] = 0xfb
	} else if opt.Compress == "lzo-no" {
		// old "comp-lzo no" option
		b = append([]byte{0xfa}, b...)
	}
	return b
}

func (d *data) WritePacket(conn net.Conn, payload []byte) (int, error) {
	var buf []byte
	if !d.state.dataCipher.isAEAD() {
		packetID := make([]byte, 4)
		localPacketID, _ := d.session.LocalPacketID()
		binary.BigEndian.PutUint32(packetID, uint32(localPacketID))
		buf = append(packetID[:], payload...)
	} else {
		buf = payload[:]
	}

	plaintext := maybeAddCompressStub(buf, d.options)
	encrypted, err := d.encrypt(plaintext)

	if err != nil {
		return 0, fmt.Errorf("%w:%s", errCannotEncrypt, err)
	}

	// eventually we'll need to write the keyID here too, from session.
	keyID := 0
	header := byte((pDataV1 << 3) | (keyID & 0x07))
	panicIfFalse(header == byte(0x30), "expected header == 0x30")
	buf = append([]byte{header}, encrypted...)
	buf = maybeAddSizeFrame(conn, buf)

	logger.Debug("data: write packet")
	logger.Debugf(hex.Dump(buf))

	return conn.Write(buf)
}

//
// read + decrypt
//

func (d *data) decrypt(encrypted []byte) ([]byte, error) {
	if len(d.state.hmacKeyRemote) == 0 {
		logger.Error("decrypt: not ready yet")
		return []byte{}, errCannotDecrypt
	}
	encryptedData, err := d.DecodeEncryptedPayload(encrypted, d.state)
	if err != nil {
		return []byte{}, fmt.Errorf("%w:%s", errCannotDecrypt, err)
	}
	plainText, err := d.state.dataCipher.decrypt(
		d.state.cipherKeyRemote[:],
		encryptedData.iv,
		encryptedData.ciphertext,
		encryptedData.aead)
	if err != nil {
		return []byte{}, fmt.Errorf("%w:%s", errCannotDecrypt, err)
	}
	return plainText, nil
}

// encrypteData holds the different parts needed to decrypt an encrypted data
// packet.
type encryptedData struct {
	iv         []byte
	ciphertext []byte
	aead       []byte
}

func decodeEncryptedPayloadAEAD(buf []byte, state *dataChannelState) (*encryptedData, error) {
	// Sample AES-GCM head: (v1 though, we're doing v1 here. I'm not sure if there're differences)
	//   48000001 00000005 7e7046bd 444a7e28 cc6387b1 64a4d6c1 380275a...
	//   [ OP32 ] [seq # ] [             auth tag            ] [ payload ... ]
	//            [4-byte
	//            IV head]

	// preconditions

	if len(buf) == 0 || len(buf) < 20 {
		return &encryptedData{}, fmt.Errorf("too short: %d bytes", len(buf))
	}
	if len(state.hmacKeyRemote) < 8 {
		return &encryptedData{}, fmt.Errorf("bad remote hmac")
	}
	remoteHMAC := state.hmacKeyRemote[:8]
	packet_id := buf[:4]

	// we need to swap because decryption expects payload|tag
	// but we've got tag | payload instead
	payload := &bytes.Buffer{}
	payload.Write(buf[20:])  // ciphertext
	payload.Write(buf[4:20]) // tag

	// iv := packetID | remoteHMAC
	iv := &bytes.Buffer{}
	iv.Write(packet_id)
	iv.Write(remoteHMAC)

	encrypted := &encryptedData{
		iv:         iv.Bytes(),
		ciphertext: payload.Bytes(),
		aead:       packet_id,
	}
	return encrypted, nil
}

func decodeEncryptedPayloadNonAEAD(buf []byte, state *dataChannelState) (*encryptedData, error) {
	if len(buf) < 28 {
		return &encryptedData{}, fmt.Errorf("too short: %d bytes", len(buf))
	}

	hashSize := state.hmacSize
	key := state.hmacKeyRemote[:hashSize]

	blockSize := state.dataCipher.blockSize()
	recvMAC := buf[:hashSize]
	iv := buf[hashSize : hashSize+blockSize]
	cipherText := buf[hashSize+blockSize:]

	// TODO instead of instantiating it each time, we can call Reset()
	mac := hmac.New(state.hmac, key)
	mac.Write(iv)
	mac.Write(cipherText)
	calcMAC := mac.Sum(nil)

	if !hmac.Equal(calcMAC, recvMAC) {
		return &encryptedData{}, fmt.Errorf("%w:%s", errCannotDecrypt, errBadHMAC)
	}

	encrypted := &encryptedData{
		iv:         iv,
		ciphertext: cipherText,
		aead:       []byte{},
	}
	return encrypted, nil
}

func (d *data) ReadPacket(p *packet) ([]byte, error) {
	if len(p.payload) == 0 {
		return []byte{}, fmt.Errorf("%w:%s", errCannotDecrypt, "empty payload")
	}
	panicIfFalse(p.isData(), "ReadPacket expects data packet")

	plaintext, err := d.decrypt(p.payload)
	if err != nil {
		return []byte{}, err
	}

	// get plaintext payload from the decrypted plaintext
	return maybeDecompress(plaintext, d.state, d.options)
}

// decompress de-serializes the data from the payload according to the framing
// given by different compression methods. only the different no-compression
// modes are supported at the moment.
func maybeDecompress(b []byte, st *dataChannelState, opt *Options) ([]byte, error) {
	var compr byte // compression type
	var payload []byte
	if st.dataCipher.isAEAD() {
		if opt.Compress == "stub" || opt.Compress == "lzo-no" {
			compr = b[0]
			payload = b[1:]
		} else {
			compr = 0x00
			payload = b[:]
		}
	} else {
		remotePacketID := packetID(binary.BigEndian.Uint32(b[:4]))
		if remotePacketID <= st.RemotePacketID() {
			logger.Errorf("possible replay attack")
			return payload, errReplayAttack
		}
		st.SetRemotePacketID(remotePacketID)
		compr = b[4]
		payload = b[5:]
	}
	switch compr {
	case 0xfb:
		// compression stub swap:
		// we get the last byte and replace the compression byte
		end := payload[len(payload)-1]
		b := payload[:len(payload)-1]
		payload = append([]byte{end}, b...)
	case 0x00, 0xfa:
		// do nothing
		// 0x00 is compress-no,
		// 0xfa is the old no compression or comp-lzo no case.
		// http://build.openvpn.net/doxygen/comp_8h_source.html
		// see: https://community.openvpn.net/openvpn/ticket/952#comment:5
	default:
		errMsg := fmt.Sprintf("cannot handle compression:%x", compr)
		return []byte{}, fmt.Errorf("%w:%s", errBadCompression, errMsg)
	}
	return payload, nil
}
