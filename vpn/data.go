package vpn

//
// OpenVPN data channel
//

import (
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"log"
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
)

type keySlot [64]byte

// data represents the data channel, that will encrypt and decrypt the tunnel payloads.
// data implements the dataHandler interface.
type data struct {
	options *Options
	session *session
	state   *dataChannelState
}

// dataChannelState is the state of the data channel.
// TODO add mutex to protect updates to remotePacketID
type dataChannelState struct {
	dataCipher      dataCipher
	hmac            func() hash.Hash
	remotePacketID  uint32
	cipherKeyLocal  keySlot
	cipherKeyRemote keySlot
	hmacKeyLocal    keySlot
	hmacKeyRemote   keySlot
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

// newDataFromOptions returns a new data object, initialized with the
// options given. it also returns any error raised.
func newDataFromOptions(opt *Options, s *session) (*data, error) {
	state := &dataChannelState{}
	data := &data{options: opt, session: s, state: state}
	log.Println("Setting cipher:", opt.Cipher)
	dataCipher, err := newDataCipherFromCipherSuite(opt.Cipher)
	if err != nil {
		return data, err
	}
	data.state.dataCipher = dataCipher
	log.Println("Setting auth:", opt.Auth)
	hmac, ok := newHMACFactory(strings.ToLower(opt.Auth))
	if !ok {
		return data, fmt.Errorf("%w:%s", errBadInput, "no such mac")
	}
	data.state.hmac = hmac
	return data, nil
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

	log.Printf("Cipher key local:  %x\n", keyLocal)
	log.Printf("Cipher key remote: %x\n", keyRemote)
	log.Printf("Hmac key local:    %x\n", hmacLocal)
	log.Printf("Hmac key remote:   %x\n", hmacRemote)
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

	// TODO refactor with packet
	if d.state.dataCipher.isAEAD() {
		packetID := make([]byte, 4)
		binary.BigEndian.PutUint32(packetID, d.session.LocalPacketID())
		// TODO use keySlot as type, this could be methods in state.
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
		// log.Println("non aead: adding packetid prefix")
		packetID := make([]byte, 4)
		binary.BigEndian.PutUint32(packetID, d.session.LocalPacketID())
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
	// TODO this can be handled in packet.go and clean up the implementation.
	keyID := 0
	header := byte((pDataV1 << 3) | (keyID & 0x07))
	panicIfFalse(header == byte(0x30), "expected header == 0x30")
	buf = append([]byte{header}, encrypted...)
	buf = maybeAddSizeFrame(conn, buf)
	// TODO if extra verbose
	//log.Println("data: write packet")
	//fmt.Println(hex.Dump(buf))
	return conn.Write(buf)
}

//
// read + decrypt
//

func (d *data) decrypt(encrypted []byte) []byte {
	if d.state.dataCipher.isAEAD() {
		return d.decryptAEAD(encrypted)
	}
	return d.decryptV1(encrypted)
}

// TODO return errors
func (d *data) decryptV1(encrypted []byte) []byte {
	if len(encrypted) < 28 {
		log.Fatalf("Packet too short: %d bytes\n", len(encrypted))
	}
	hashLength := getHashLength(strings.ToLower(d.options.Auth))
	bs := d.state.dataCipher.blockSize()
	recvMAC := encrypted[:hashLength]
	iv := encrypted[hashLength : hashLength+bs]
	cipherText := encrypted[hashLength+bs:]

	key := d.state.hmacKeyRemote[:hashLength]
	mac := hmac.New(d.state.hmac, key)
	mac.Write(append(iv, cipherText...))
	calcMAC := mac.Sum(nil)

	if !hmac.Equal(calcMAC, recvMAC) {
		log.Fatal("Cannot decrypt!")
	}

	plainText, err := d.state.dataCipher.decrypt(d.state.cipherKeyRemote[:], iv, cipherText, []byte(""))
	if err != nil {
		log.Fatal("Decryption error")
	}
	return plainText
}

func (d *data) decryptAEAD(payload []byte) []byte {
	// Sample AES-GCM head: (V2 though)
	//   48000001 00000005 7e7046bd 444a7e28 cc6387b1 64a4d6c1 380275a...
	//   [ OP32 ] [seq # ] [             auth tag            ] [ payload ... ]
	//            [4-byte
	//            IV head]
	if len(payload) == 0 || len(payload) < 40 {
		log.Println("WARN decryptAEAD: bad length:", len(payload))
		fmt.Println(hex.Dump(payload))
		return []byte{}
	}
	// BUG: we should not attempt to decrypt payloads until we have initialized the key material
	if len(d.state.hmacKeyRemote) == 0 {
		log.Println("WARN decryptAEAD: not ready yet")
		return []byte{}
	}
	packetID := payload[:4]
	/* BUG: for some reason that I don't understand, this is not properly parsed
	   as bytes... the tag gets mangled. but it's good if I convert it to
	   hex and back (which sorcery is this?)
	*/
	recvHex := hex.EncodeToString(payload[:])
	tagH := recvHex[8:40]
	ctH := recvHex[40:]

	iv := append(packetID, d.state.hmacKeyRemote[:8]...)
	ct, _ := hex.DecodeString(ctH)
	tag, _ := hex.DecodeString(tagH)
	reconstructed := append(ct, tag...)
	plaintext, err := d.state.dataCipher.decrypt(d.state.cipherKeyRemote[:], iv, reconstructed, packetID)

	if err != nil {
		log.Println("error", err.Error())
		return []byte{}
	}
	return plaintext
}

func (d *data) ReadPacket(p *packet) ([]byte, error) {
	if len(p.payload) == 0 {
		return []byte{}, fmt.Errorf("%w:%s", errCannotDecrypt, "empty payload")
	}
	panicIfFalse(p.isData(), "ReadPacket expects data packet")

	// TODO get error instead of relying on len
	plaintext := d.decrypt(p.payload)
	if len(plaintext) == 0 {
		log.Println("WARN handleIn: could not decrypt, skipped")
		return []byte{}, errBadInput
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
		packetID := binary.BigEndian.Uint32(b[:4])
		if int(packetID) <= int(st.remotePacketID) {
			// TODO should probably fatal
			return payload, errReplayAttack
		}
		// TODO for CBC mode the compression might need work...
		// TODO use setter method (w/ mutex)
		st.remotePacketID = packetID
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
