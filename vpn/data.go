package vpn

import (
	"crypto/hmac"
	"encoding/binary"
	"hash"
	"log"
	"net"
)

func getPingData() []byte {
	return []byte{0x2A, 0x18, 0x7B, 0xF3, 0x64, 0x1E, 0xB4, 0xCB, 0x07, 0xED, 0x2D, 0x0A, 0x98, 0x1F, 0xC7, 0x48}
}

func newData(local, remote *keySource) *data {
	q := make(chan []byte, 10)
	// TODO use names instead
	return &data{q, local, remote, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, 0, 0, nil, nil, nil}
}

type data struct {
	queue           chan []byte
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

	cipher Cipher
	// for now, just the sha1.New function
	// that needs to be initialized as:
	// hmac.New(hash, secret)
	hmac func() hash.Hash
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
	d.loadSettings()
	go d.processIncoming()
}

func (d *data) setup() {
	log.Println("==> data setup")
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

func (d *data) loadSettings() {
	log.Println("Loading settings...")
	// XXX  hardcoded for now, need to parse settings and load the needed cipher/hmac combination
	d.cipher, _ = newCipher("aes", 128, "cbc")
	d.hmac = getHMAC("sha1")
}

func (d *data) encrypt(plaintext []byte) []byte {
	bs := d.cipher.BlockSize()
	padded := padText(plaintext, bs)
	//log.Println(padded)
	if d.cipher.IsAEAD() {
		log.Fatal("aead cipher not implemented")
	}

	iv, err := genRandomBytes(bs)
	checkError(err)
	ciphertext, err := d.cipher.Encrypt(d.cipherKeyLocal, iv, padded)
	checkError(err)

	// XXX hardcoded for sha1, should add to a hash interface when I make this selectable
	hashLength := 20
	key := d.hmacKeyRemote[:hashLength]
	mac := hmac.New(d.hmac, key)
	mac.Write(append(iv, ciphertext...))
	calcMAC := mac.Sum(nil)

	payload := append(calcMAC, iv...)
	payload = append(payload, ciphertext...)
	return payload
}

func (d *data) decrypt(encrypted []byte) []byte {
	if d.cipher.IsAEAD() {
		log.Fatal("aead cipher not implemented")
	}
	return d.decryptV1(encrypted)
}

func (d *data) decryptV1(encrypted []byte) []byte {
	if len(encrypted) < 28 {
		log.Fatalf("Packet too short: %d bytes\n", len(encrypted))
	}
	// XXX hardcoded for sha1, should add to a hash interface when I make this selectable
	hashLength := 20
	bs := d.cipher.BlockSize()
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

	plainText, err := d.cipher.Decrypt(d.cipherKeyRemote, iv, cipherText)
	if err != nil {
		log.Fatal("Decryption error")
	}
	return plainText
}

func (d *data) decryptAEAD() {
	// not implemented atm, implement when adding AES-CGM cipher
}

func (d *data) send(payload []byte) {
	d.localPacketId += 1
	// log.Println("sending", len(payload), "bytes...")
	packetId := make([]byte, 4)
	binary.BigEndian.PutUint32(packetId, d.localPacketId)
	plaintext := append(packetId, 0xfa) // no compression
	plaintext = append(plaintext, payload...)
	buf := append([]byte{0x30}, d.encrypt(plaintext)...)
	d.conn.Write(buf)
}

func (d *data) handleIn(packet []byte) {
	if packet[0] != 0x30 {
		log.Fatal("Wrong data header!")
	}
	data := packet[1:]
	plaintext := d.decrypt(data)
	packetId := binary.BigEndian.Uint32(plaintext[:4])
	if int(packetId) <= int(d.remotePacketId) {
		log.Fatal("Replay attack detected, aborting!")
	}
	d.remotePacketId = packetId
	compression := plaintext[4]
	// http://build.openvpn.net/doxygen/html/comp_8h_source.html
	if compression != 0xfa {
		log.Fatal("no compression supported")
	}
	payload := plaintext[5:]
	if areBytesEqual(payload, getPingData()) {
		log.Println("Ping from server, replying...")
		d.send(getPingData())
		return
	}

	//d.outQueue.append(payload)
	log.Printf("data: %x\n", payload)
}
