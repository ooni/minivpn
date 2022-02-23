package vpn

import (
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"log"
	"net"
	"os"
	"strings"
)

func getPingData() []byte {
	return []byte{0x2A, 0x18, 0x7B, 0xF3, 0x64, 0x1E, 0xB4, 0xCB, 0x07, 0xED, 0x2D, 0x0A, 0x98, 0x1F, 0xC7, 0x48}
}

func newData(local, remote *keySource, cipher, auth string) *data {
	q := make(chan []byte, 10)
	dq := make(chan []byte, 20)
	d := &data{cipher: cipher, auth: auth, queue: q, dataQueue: dq, localKeySource: local, remoteKeySource: remote,
		remoteID: []byte{}, sessionID: []byte{}, cipherKeyLocal: []byte{}, cipherKeyRemote: []byte{},
		hmacKeyLocal: []byte{}, hmacKeyRemote: []byte{}, localPacketId: 0, remotePacketId: 0,
		conn: nil, ciph: nil}
	// FIXME get this from config file instead
	if os.Getenv("COMP_STUB") == "1" {
		d.compr = "stub"
	}
	return d
}

type data struct {
	cipher          string
	auth            string
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
	localPacketId   uint32
	remotePacketId  uint32
	conn            net.Conn
	compr           string // TODO need to to something with this mess

	ciph Cipher
	hmac func() hash.Hash
}

func (d *data) getDataChan() chan []byte {
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

func (d *data) loadCipherFromOptions() {
	log.Println("Setting cipher:", d.cipher)
	c, err := newCipherFromCipherSuite(d.cipher)
	if err != nil {
		log.Fatal("bad cipher")
	}
	d.ciph = c
	log.Println("Setting auth:", d.auth)
	d.hmac = getHMAC(strings.ToLower(d.auth))
}

func (d *data) encrypt(plaintext []byte) []byte {
	bs := d.ciph.BlockSize()
	var padded []byte

	if d.compr == "stub" {
		// for the compression stub, we need to send the first byte to
		// the last one, after adding pading
		lp := len(plaintext)
		end := plaintext[lp-1]
		padded = padText(plaintext[:lp-1], bs)
		padded[len(padded)-1] = end
	} else {
		padded = padText(plaintext, bs)
	}

	if d.ciph.IsAEAD() {
		packetId := make([]byte, 4)
		binary.BigEndian.PutUint32(packetId, d.localPacketId)
		iv := append(packetId, d.hmacKeyLocal[:8]...)

		ct, err := d.ciph.Encrypt(d.cipherKeyLocal, iv, padded, packetId)
		if err != nil {
			log.Println("error:", err)
			return []byte("")
		}

		// openvpn uses tag | payload
		tag := ct[len(ct)-16:]
		payload := ct[:len(ct)-16]

		p := append(packetId, tag...)
		p = append(p, payload...)
		return p
	}

	// For iv generation, OpenVPN uses a nonce-based PRNG that is initially seeded with
	// OpenSSL RAND_bytes function. I guess this is good enough for our purposes, for now
	iv, err := genRandomBytes(bs)
	checkError(err)
	ciphertext, err := d.ciph.Encrypt(d.cipherKeyLocal, iv, padded, []byte(""))
	checkError(err)

	hashLength := getHashLength(strings.ToLower(d.auth))
	key := d.hmacKeyLocal[:hashLength]
	mac := hmac.New(d.hmac, key)
	mac.Write(append(iv, ciphertext...))
	calcMAC := mac.Sum(nil)

	payload := append(calcMAC, iv...)
	payload = append(payload, ciphertext...)
	return payload
}

func (d *data) decrypt(encrypted []byte) []byte {
	if d.ciph.IsAEAD() {
		return d.decryptAEAD(encrypted)
	}
	return d.decryptV1(encrypted)
}

func (d *data) decryptV1(encrypted []byte) []byte {
	if len(encrypted) < 28 {
		log.Fatalf("Packet too short: %d bytes\n", len(encrypted))
	}
	hashLength := getHashLength(strings.ToLower(d.auth))
	bs := d.ciph.BlockSize()
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

	plainText, err := d.ciph.Decrypt(d.cipherKeyRemote, iv, cipherText, []byte(""))
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
	if len(dat) == 0 {
		return []byte{}
	}
	packetId := dat[:4]
	// weird sorcery:
	// for some reason that I don't understand, this is not properly parsed
	// as bytes... the tag gets mangled. but it's good if I convert it to hex and back...
	recvHex := hex.EncodeToString(dat[:])
	tagH := recvHex[8:40]
	ctH := recvHex[40:]

	iv := append(packetId, d.hmacKeyRemote[:8]...)
	ct, _ := hex.DecodeString(ctH)
	tag, _ := hex.DecodeString(tagH)
	reconstructed := append(ct, tag...)
	plaintext, err := d.ciph.Decrypt(d.cipherKeyRemote, iv, reconstructed, packetId)

	if err != nil {
		log.Println("error", err.Error())
		return []byte{}
	}
	return plaintext
}

func (d *data) send(payload []byte) {
	d.localPacketId += 1
	plaintext := []byte("")
	if !d.ciph.IsAEAD() {
		log.Println("non aead: adding packetid prefix")
		packetId := make([]byte, 4)
		binary.BigEndian.PutUint32(packetId, d.localPacketId)
		plaintext = packetId[:]
	} else {
		plaintext = payload[:]
	}

	if d.compr == "stub" {
		// compress
		plaintext = append(plaintext, plaintext[0])
		plaintext[0] = 0xfb
	} else if d.compr == "lzo-no" {
		// this is the case for the old "comp-lzo no"
		plaintext = append([]byte{0xfa}, plaintext...) // no compression
	} else {
		// just nothing
	}

	buf := append([]byte{0x30}, d.encrypt(plaintext)...)
	d.conn.Write(buf)
}

func (d *data) handleIn(packet []byte) {
	if packet[0] != 0x30 {
		log.Fatal("Wrong data header!")
	}
	data := packet[1:]
	plaintext := d.decrypt(data)
	if len(plaintext) == 0 {
		log.Println("could not decrypt, skipped")
		return
	}

	var compression byte
	var payload []byte
	if d.ciph.IsAEAD() {
		if d.compr == "stub" || d.compr == "lzo-no" {
			compression = plaintext[0]
			payload = plaintext[1:]
		} else {
			compression = 0x00
			payload = plaintext[:]
		}
	} else {
		packetId := binary.BigEndian.Uint32(plaintext[:4])
		if int(packetId) <= int(d.remotePacketId) {
			log.Fatal("Replay attack detected, aborting!")
		}
		// TODO for CBC mode the compression might need work...
		d.remotePacketId = packetId
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
		/*
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
