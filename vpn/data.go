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

// dataChannelKey represents  one of the key sources that have been negotiated
// over the control channel, and from which we will derive local and remote keys for encryption and decrption
// over the data channel. The index refers to the short key_id that is passed in the lower 3 bits if a packet header.
// The setup of the keys for a given data channel (that is, for every key_id) is made by expanding the
// keysources using the prf function.
// Do note that we are not yet implementing key renegotiation - but the index is provided for convenience
// when/if we support that in the future.
type dataChannelKey struct {
	index  uint32
	ready  bool
	local  *keySource
	remote *keySource
	mu     sync.Mutex
}

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

func (d *data) encrypt(plaintext []byte) ([]byte, error) {
	bs := d.state.dataCipher.blockSize()
	var padded []byte
	var err error

	/* TODO: deal with compression in a separate routine */
	if d.options.Compress == "stub" {
		// for the compression stub, we need to send the first byte to
		// the last one, after padding
		lp := len(plaintext)
		end := plaintext[lp-1]
		padded, err = bytesPadPKCS7(plaintext[:lp-1], bs)
		if err != nil {
			return nil, err
		}
		padded[len(padded)-1] = end
	} else {
		padded, err = bytesPadPKCS7(plaintext, bs)
		if err != nil {
			return nil, err
		}
	}

	// TODO refactor with packet
	if d.state.dataCipher.isAEAD() {
		packetID := make([]byte, 4)
		binary.BigEndian.PutUint32(packetID, d.session.LocalPacketID())
		// TODO use keySlot as type
		iv := append(packetID, d.state.hmacKeyLocal[:8]...)

		ct, err := d.state.dataCipher.encrypt(d.state.cipherKeyLocal[:], iv, padded, packetID)
		if err != nil {
			log.Println("error:", err)
			return []byte{}, err
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
	iv, err := genRandomBytes(bs)
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

func (d *data) decrypt(encrypted []byte) []byte {
	if d.state.dataCipher.isAEAD() {
		return d.decryptAEAD(encrypted)
	}
	return d.decryptV1(encrypted)
}

func (d *data) decryptV1(encrypted []byte) []byte {
	// TODO return error instead
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

func (d *data) WritePacket(conn net.Conn, payload []byte) (int, error) {
	var plaintext []byte
	if !d.state.dataCipher.isAEAD() {
		// log.Println("non aead: adding packetid prefix")
		packetID := make([]byte, 4)
		binary.BigEndian.PutUint32(packetID, d.session.LocalPacketID())
		plaintext = packetID[:]
	} else {
		plaintext = payload[:]
	}

	if d.options.Compress == "stub" {
		// compress
		plaintext = append(plaintext, plaintext[0])
		plaintext[0] = 0xfb
	} else if d.options.Compress == "lzo-no" {
		// this is the case for the old "comp-lzo no"
		plaintext = append([]byte{0xfa}, plaintext...) // no compression
	}

	encrypted, err := d.encrypt(plaintext)
	if err != nil {
		// TODO define encryptErr
		log.Println("encryption error: %w", err)
		return 0, err
	}

	// TODO use packet
	buf := append([]byte{0x30}, encrypted...)
	buf = maybeAddSizeFrame(conn, buf)

	log.Println("data: write packet")
	fmt.Println(hex.Dump(buf))

	return conn.Write(buf)
}

// TODO pass data []byte, this is not (yet) a packet type
func (d *data) ReadPacket(packet []byte) ([]byte, error) {
	if len(packet) == 0 {
		log.Println("ERROR handleIn: empty packet")
		// TODO define error
		return []byte{}, errBadInput
	}

	// 0x30 is just pDataV1 + key_id=0
	if packet[0] != 0x30 {
		log.Println("ERROR handleIn: wrong data header")
		return []byte{}, errBadInput
	}

	// TODO so this is essentially:
	// plaintext: decrypt(ctx, packet.payload)

	data := packet[1:]
	plaintext := d.decrypt(data)
	if len(plaintext) == 0 {
		log.Println("WARN handleIn: could not decrypt, skipped")
		return []byte{}, errBadInput
	}

	/* what follows deals with compression and de-serializes the "real"
	   plaintext payload from the decrypted plaintext */

	// ------------- begin compression routine ------------------------------
	// TODO can pass a state type, right?
	// pt = decompress(plaintext) ???

	var compression byte
	var payload []byte
	if d.state.dataCipher.isAEAD() {
		if d.options.Compress == "stub" || d.options.Compress == "lzo-no" {
			compression = plaintext[0]
			payload = plaintext[1:]
		} else {
			compression = 0x00
			payload = plaintext[:]
		}
	} else {
		packetID := binary.BigEndian.Uint32(plaintext[:4])
		if int(packetID) <= int(d.state.remotePacketID) {
			log.Fatal("Replay attack detected, aborting!")
		}
		// TODO for CBC mode the compression might need work...
		// TODO use setter method (w/ mutex)
		d.state.remotePacketID = packetID
		compression = plaintext[4]
		payload = plaintext[5:]
	}
	if compression == 0x00 {
		// all good, no need to do anything else
	} else if compression == 0xfa {
		// do nothing, this is the old no compression
		// or comp-lzo no case.
		// http://build.openvpn.net/doxygen/comp_8h_source.html
		// see: https://community.openvpn.net/openvpn/ticket/952#comment:5
	} else if compression == 0xfb {
		// compression stub swap:
		// we get the last byte and replace the compression byte
		end := payload[len(payload)-1]
		b := payload[:len(payload)-1]
		payload = append([]byte{end}, b...)
	} else {
		log.Printf("WARN no compression supported: %x %d\n", compression, compression)
		return []byte{}, errBadInput
	}
	// ------------- end compression routine ------------------------------

	return payload, nil
}
