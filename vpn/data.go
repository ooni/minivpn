package vpn

import (
	"hash"
	"log"
)

func getPingData() []byte {
	return []byte{0x2A, 0x18, 0x7B, 0xF3, 0x64, 0x1E, 0xB4, 0xCB, 0x07, 0xED, 0x2D, 0x0A, 0x98, 0x1F, 0xC7, 0x48}
}

func newData(local, remote *keySource) *data {
	q := make(chan []byte, 10)
	return &data{q, local, remote, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, nil, nil}
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

func (d *data) encrypt() {
	/*
	          bs = self.cipher.BLOCK_SIZE
	          n = bs - (len(plaintext) % bs)
	          padded = plaintext + b"".join(bytes([n]) for _ in range(n))

	          if self.cipher.AEAD:
	   	   iv = packet_id.to_bytes(4, "big") + self.hmac_key_local[:8]
	   	   ad = packet_id.to_bytes(4, "big")
	   	   ct = self.cipher.encrypt(self.cipher_key_local, iv, padded, ad)

	   	   # openvpn uses tag | payload, cryptography(mod) uses payload | tag.
	   	   # S W A P P Y
	   	   tag = ct[-16:]
	   	   payload = ct[:-16]

	   	   self.log.debug(
	   	       "aead enc %d bytes (%d pt bytes): iv=%s ad=%s",
	   	       len(ct),
	   	       len(plaintext),
	   	       shex(iv),
	   	       shex(ad),
	   	   )

	   	   return ad + tag + payload

	          iv = getrandbytes(bs)

	          ciphertext = self.cipher.encrypt(self.cipher_key_local, iv, padded)

	          hmac_ = self.hmac.hash(self.hmac_key_local, iv + ciphertext)
	          self.log.debug(
	   	   "encrypted %d bytes (%d pt bytes): iv=%s hmac=%s",
	   	   len(ciphertext),
	   	   len(plaintext),
	   	   shex(iv),
	   	   shex(hmac_),
	          )
	          return hmac_ + iv + ciphertext
	*/
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
	return nil
	/*
	   bs = self.cipher.BLOCK_SIZE
	   hmac_ = data[: self.hmac.HASH_LENGTH]
	   iv = data[self.hmac.HASH_LENGTH : self.hmac.HASH_LENGTH + bs]
	   ciphertext = data[self.hmac.HASH_LENGTH + bs :]

	   our_hmac = self.hmac.hash(self.hmac_key_remote, iv + ciphertext)
	   if not hmac.compare_digest(our_hmac, hmac_):
	       self.log.error(
	           "cannot decrypt %d bytes: iv=%s hmac=%s local_hmac=%s",
	           len(data),
	           shex(iv),
	           shex(hmac_),
	           shex(our_hmac),
	       )
	       raise InvalidHMACError()

	   plaintext = self.cipher.decrypt(self.cipher_key_remote, iv, ciphertext)

	   # remove padding
	   n = plaintext[-1]
	   assert n < len(plaintext) and n <= bs, (n, len(plaintext), bs)
	   plaintext = plaintext[:-n]

	   self.log.debug(
	       "decrypted %d bytes (%d pt bytes): iv=%s hmac=%s",
	       len(ciphertext),
	       len(plaintext),
	       shex(iv),
	       shex(hmac_),
	   )
	   return plaintext
	*/
}

func (d *data) decryptAEAD() {
	// not implemented atm, implement when adding AES-CGM cipher
}

func (d *data) handleIn(packet []byte) {
	log.Println("RECEIVED DATA PACKET", len(packet))
	if packet[0] != 0x30 {
		log.Fatal("Wrong data header!")
	}
	data := packet[1:]
	log.Printf("received %d raw data bytes\n", len(data))
	log.Println("now should decrypt...")

	/*
	   plaintext = self.decrypt(data)

	   packet_id = plaintext[:4]
	   # FIXME do stuff with packet_id
	   compression = plaintext[4]

	   # http://build.openvpn.net/doxygen/html/comp_8h_source.html
	   assert compression == 0xfa  # no compression

	   payload = plaintext[5:]

	   if payload == PING_DATA:
	       self.log.debug("PING received, replied")
	       self.send(PING_DATA)
	       return

	   self.out_queue.append(payload)
	   self.log.debug("data: %r", payload)
	*/

}
