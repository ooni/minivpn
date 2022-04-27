package vpn

import (
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"log"
	"net"
	"strings"
	"sync"
)

func getPingData() []byte {
	return []byte{0x2A, 0x18, 0x7B, 0xF3, 0x64, 0x1E, 0xB4, 0xCB, 0x07, 0xED, 0x2D, 0x0A, 0x98, 0x1F, 0xC7, 0x48}
}

func newData(local, remote *keySource, o *Options) *data {
	q := make(chan []byte, 10)
	dq := make(chan []byte, 20)
	d := &data{
		opts:  o,
		queue: q, dataQueue: dq,
		localKeySource:  local,
		remoteKeySource: remote,
	}
	return d
}

type data struct {
	/* get this from options */
	// compr  string // TODO need to to something with this mess

	opts            *Options
	queue           chan []byte
	dataQueue       chan []byte
	localKeySource  *keySource
	remoteKeySource *keySource
	remoteID        []byte
	sessionID       []byte
	cipherKeyLocal  []byte
	cipherKeyRemote []byte
	hmacKeyLocal    []byte
	hmacKeyRemote   []byte
	localPacketID   uint32
	remotePacketID  uint32
	conn            net.Conn
	mu              sync.Mutex

	c    dataCipher
	hmac func() hash.Hash
}

func (d *data) dataChan() chan []byte {
	return d.dataQueue
}

func (d *data) processIncoming() {
	for {
		select {
		case data := <-d.queue:
			d.handleIn(data)
		}

	}
}

func (d *data) initSession(c *control) {
	d.remoteID = c.RemoteID
	d.sessionID = c.SessionID
	d.conn = c.conn
	d.loadCipherFromOptions()
	go d.processIncoming()
}

func (d *data) setup() {
	master := prf(
		d.localKeySource.preMaster,
		[]byte("OpenVPN master secret"),
		d.localKeySource.r1,
		d.remoteKeySource.r1,
		[]byte{}, []byte{},
		48)

	keys := prf(
		master,
		[]byte("OpenVPN key expansion"),
		d.localKeySource.r2,
		d.remoteKeySource.r2,
		d.sessionID, d.remoteID,
		256)

	d.cipherKeyLocal, d.hmacKeyLocal = keys[0:64], keys[64:128]
	d.cipherKeyRemote, d.hmacKeyRemote = keys[128:192], keys[192:256]

	log.Printf("Cipher key local:  %x\n", d.cipherKeyLocal)
	log.Printf("Cipher key remote: %x\n", d.cipherKeyRemote)
	log.Printf("Hmac key local:    %x\n", d.hmacKeyLocal)
	log.Printf("Hmac key remote:   %x\n", d.hmacKeyRemote)
}

// TODO bubble errors up
func (d *data) loadCipherFromOptions() {
	log.Println("Setting cipher:", d.opts.Cipher)
	c, err := newCipherFromCipherSuite(d.opts.Cipher)
	if err != nil {
		log.Fatal("bad cipher")
	}
	d.c = c
	log.Println("Setting auth:", d.opts.Auth)
	h, ok := getHMAC(strings.ToLower(d.opts.Auth))
	if !ok {
		log.Println("error: no such mac")
		return
	}
	d.hmac = h
}

func (d *data) encrypt(plaintext []byte) []byte {
	bs := d.c.blockSize()
	var padded []byte

	if d.opts.Compress == "stub" {
		// for the compression stub, we need to send the first byte to
		// the last one, after padding
		lp := len(plaintext)
		end := plaintext[lp-1]
		padded = padText(plaintext[:lp-1], bs)
		padded[len(padded)-1] = end
	} else {
		padded = padText(plaintext, bs)
	}

	if d.c.isAEAD() {
		packetID := make([]byte, 4)
		binary.BigEndian.PutUint32(packetID, d.localPacketID)
		iv := append(packetID, d.hmacKeyLocal[:8]...)

		ct, err := d.c.encrypt(d.cipherKeyLocal, iv, padded, packetID)
		if err != nil {
			log.Println("error:", err)
			return []byte("")
		}

		// openvpn uses tag | payload
		tag := ct[len(ct)-16:]
		payload := ct[:len(ct)-16]

		p := append(packetID, tag...)
		p = append(p, payload...)
		return p
	}

	// For iv generation, OpenVPN uses a nonce-based PRNG that is initially seeded with
	// OpenSSL RAND_bytes function. I guess this is good enough for our purposes, for now
	iv, err := genRandomBytes(bs)
	checkError(err)
	ciphertext, err := d.c.encrypt(d.cipherKeyLocal, iv, padded, []byte(""))
	checkError(err)

	hashLength := getHashLength(strings.ToLower(d.opts.Auth))
	key := d.hmacKeyLocal[:hashLength]
	mac := hmac.New(d.hmac, key)
	mac.Write(append(iv, ciphertext...))
	calcMAC := mac.Sum(nil)

	payload := append(calcMAC, iv...)
	payload = append(payload, ciphertext...)
	return payload
}

func (d *data) decrypt(encrypted []byte) []byte {
	if d.c.isAEAD() {
		return d.decryptAEAD(encrypted)
	}
	return d.decryptV1(encrypted)
}

func (d *data) decryptV1(encrypted []byte) []byte {
	if len(encrypted) < 28 {
		log.Fatalf("Packet too short: %d bytes\n", len(encrypted))
	}
	hashLength := getHashLength(strings.ToLower(d.opts.Auth))
	bs := d.c.blockSize()
	recvMAC := encrypted[:hashLength]
	iv := encrypted[hashLength : hashLength+bs]
	cipherText := encrypted[hashLength+bs:]

	key := d.hmacKeyRemote[:hashLength]
	mac := hmac.New(d.hmac, key)
	mac.Write(append(iv, cipherText...))
	calcMAC := mac.Sum(nil)

	if !hmac.Equal(calcMAC, recvMAC) {
		log.Fatal("Cannot decrypt!")
	}

	plainText, err := d.c.decrypt(d.cipherKeyRemote, iv, cipherText, []byte(""))
	if err != nil {
		log.Fatal("Decryption error")
	}
	return plainText
}

func (d *data) decryptAEAD(dat []byte) []byte {
	// Sample AES-GCM head: (V2 though)
	//   48000001 00000005 7e7046bd 444a7e28 cc6387b1 64a4d6c1 380275a...
	//   [ OP32 ] [seq # ] [             auth tag            ] [ payload ... ]
	//            [4-byte
	//            IV head]
	if len(dat) == 0 || len(dat) < 40 {
		log.Println("WARN decryptAEAD: bad length")
		return []byte{}
	}
	// BUG: we should not attempt to decrypt payloads until we have initialized the key material
	if len(d.hmacKeyRemote) == 0 {
		log.Println("WARN decryptAEAD: not ready yet")
		return []byte{}
	}
	packetID := dat[:4]
	// for some reason that I don't understand, this is not properly parsed
	// as bytes... the tag gets mangled. but it's good if I convert it to hex and back (which sorcery is this?)
	recvHex := hex.EncodeToString(dat[:])
	tagH := recvHex[8:40]
	ctH := recvHex[40:]

	iv := append(packetID, d.hmacKeyRemote[:8]...)
	ct, _ := hex.DecodeString(ctH)
	tag, _ := hex.DecodeString(tagH)
	reconstructed := append(ct, tag...)
	plaintext, err := d.c.decrypt(d.cipherKeyRemote, iv, reconstructed, packetID)

	if err != nil {
		log.Println("error", err.Error())
		return []byte{}
	}
	return plaintext
}

func (d *data) send(payload []byte) {
	// TODO use a channel here instead?
	d.mu.Lock()
	defer d.mu.Unlock()
	d.localPacketID++
	plaintext := []byte("")
	if !d.c.isAEAD() {
		log.Println("non aead: adding packetid prefix")
		packetID := make([]byte, 4)
		binary.BigEndian.PutUint32(packetID, d.localPacketID)
		plaintext = packetID[:]
	} else {
		plaintext = payload[:]
	}

	if d.opts.Compress == "stub" {
		// compress
		plaintext = append(plaintext, plaintext[0])
		plaintext[0] = 0xfb
	} else if d.opts.Compress == "lzo-no" {
		// this is the case for the old "comp-lzo no"
		plaintext = append([]byte{0xfa}, plaintext...) // no compression
	} else {
		// just nothing
	}

	buf := append([]byte{0x30}, d.encrypt(plaintext)...)
	if isTCP(d.opts.Proto) {
		buf = toSizeFrame(buf)
	}
	d.conn.Write(buf)
}

func (d *data) handleIn(packet []byte) {
	if len(packet) == 0 {
		log.Println("ERROR handleIn: empty packet")
		return
	}
	if packet[0] != 0x30 {
		log.Println("ERROR handleIn: wrong data header")
		return
	}
	data := packet[1:]
	plaintext := d.decrypt(data)
	if len(plaintext) == 0 {
		log.Println("WARN handleIn: could not decrypt, skipped")
		return
	}

	var compression byte
	var payload []byte
	if d.c.isAEAD() {
		if d.opts.Compress == "stub" || d.opts.Compress == "lzo-no" {
			compression = plaintext[0]
			payload = plaintext[1:]
		} else {
			compression = 0x00
			payload = plaintext[:]
		}
	} else {
		packetID := binary.BigEndian.Uint32(plaintext[:4])
		if int(packetID) <= int(d.remotePacketID) {
			log.Fatal("Replay attack detected, aborting!")
		}
		// TODO for CBC mode the compression might need work...
		d.remotePacketID = packetID
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
		/* I don't think I'm going to use this anytime soon, better remove
		} else if compression == 0x45 {
			log.Println("DEBUG (lz4)")
			log.Println(hex.EncodeToString(payload))

			end := payload[len(payload)-1]
			b := payload[:len(payload)-1]
			payload = append([]byte{end}, b...)
			log.Println(hex.EncodeToString(payload))

			decompr := make([]byte, len(payload)*20)
			l, err := lz4.UncompressBlock(payload, decompr)
			if err != nil {
				log.Println("lz4 error:", err.Error())
				return
			}
			payload = decompr[:l]
			log.Println("payload:", payload)
		} else if compression == 0x2a {
			log.Println("LZO compression 0x2a not supported")
		*/
	} else {
		log.Printf("WARN no compression supported: %x %d\n", compression, compression)
	}

	if areBytesEqual(payload, getPingData()) {
		log.Println("openvpn-ping, sending reply")
		d.send(getPingData())
		return
	}

	// log.Printf("data: %x\n", payload)
	d.dataQueue <- payload
}
