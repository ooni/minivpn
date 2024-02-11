package datachannel

//
// Functions for encoding & writing packets
//

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ooni/minivpn/internal/bytesx"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
)

// encryptAndEncodePayloadAEAD peforms encryption and encoding of the payload in AEAD modes (i.e., AES-GCM).
// TODO(ainghazal): for testing we can pass both the state object and the encryptFn
func encryptAndEncodePayloadAEAD(log model.Logger, padded []byte, session *session.Manager, state *dataChannelState) ([]byte, error) {
	nextPacketID, err := session.LocalDataPacketID()
	if err != nil {
		return []byte{}, fmt.Errorf("bad packet id")
	}

	// in AEAD mode, we authenticate:
	// - 1 byte: opcode/key
	// - 3 bytes: peer-id (we're using P_DATA_V2)
	// - 4 bytes: packet-id
	aead := &bytes.Buffer{}
	aead.WriteByte(opcodeAndKeyHeader(session))
	bytesx.WriteUint24(aead, uint32(session.TunnelInfo().PeerID))
	bytesx.WriteUint32(aead, uint32(nextPacketID))

	// the iv is the packetID (again) concatenated with the 8 bytes of the
	// key derived for local hmac (which we do not use for anything else in AEAD mode).
	iv := &bytes.Buffer{}
	bytesx.WriteUint32(iv, uint32(nextPacketID))
	iv.Write(state.hmacKeyLocal[:8])

	data := &plaintextData{
		iv:        iv.Bytes(),
		plaintext: padded,
		aead:      aead.Bytes(),
	}

	encryptFn := state.dataCipher.encrypt
	encrypted, err := encryptFn(state.cipherKeyLocal[:], data)
	if err != nil {
		return []byte{}, err
	}

	// some reordering, because openvpn uses tag | payload
	boundary := len(encrypted) - 16
	tag := encrypted[boundary:]
	ciphertext := encrypted[:boundary]

	// we now write to the output buffer
	out := bytes.Buffer{}
	out.Write(data.aead) // opcode|peer-id|packet_id
	out.Write(tag)
	out.Write(ciphertext)
	return out.Bytes(), nil

}

// assign the random function to allow using a deterministic one in tests.
var genRandomFn = bytesx.GenRandomBytes

// encryptAndEncodePayloadNonAEAD peforms encryption and encoding of the payload in Non-AEAD modes (i.e., AES-CBC).
func encryptAndEncodePayloadNonAEAD(log model.Logger, padded []byte, session *session.Manager, state *dataChannelState) ([]byte, error) {
	// For iv generation, OpenVPN uses a nonce-based PRNG that is initially seeded with
	// OpenSSL RAND_bytes function. I am assuming this is good enough for our current purposes.
	blockSize := state.dataCipher.blockSize()

	iv, err := genRandomFn(int(blockSize))
	if err != nil {
		return nil, err
	}
	data := &plaintextData{
		iv:        iv,
		plaintext: padded,
		aead:      nil,
	}

	encryptFn := state.dataCipher.encrypt
	ciphertext, err := encryptFn(state.cipherKeyLocal[:], data)
	if err != nil {
		return nil, err
	}

	state.hmacLocal.Reset()
	state.hmacLocal.Write(iv)
	state.hmacLocal.Write(ciphertext)
	computedMAC := state.hmacLocal.Sum(nil)

	out := &bytes.Buffer{}
	out.WriteByte(opcodeAndKeyHeader(session))
	bytesx.WriteUint24(out, uint32(session.TunnelInfo().PeerID))

	out.Write(computedMAC)
	out.Write(iv)
	out.Write(ciphertext)
	return out.Bytes(), nil
}

// doCompress adds compression bytes if needed by the passed compression options.
// if the compression stub is on, it sends the first byte to the last position,
// and it adds the compression preamble, according to the spec. compression
// lzo-no also adds a preamble. It returns a byte array and an error if the
// operation could not be completed.
func doCompress(b []byte, compress model.Compression) ([]byte, error) {
	switch compress {
	case "stub":
		// compression stub: send first byte to last
		// and add 0xfb marker on the first byte.
		b = append(b, b[0])
		b[0] = 0xfb
	case "lzo-no":
		// old "comp-lzo no" option
		b = append([]byte{0xfa}, b...)
	}
	return b, nil
}

var errPadding = errors.New("padding error")

// doPadding does pkcs7 padding of the encryption payloads as
// needed. if we're using the compression stub the padding is applied without taking the
// trailing bit into account. it returns the resulting byte array, and an error
// if the operatio could not be completed.
func doPadding(b []byte, compress model.Compression, blockSize uint8) ([]byte, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("%w: %s", errPadding, "nothing to pad")
	}
	if compress == "stub" {
		// if we're using the compression stub
		// we need to account for a trailing byte
		// that we have appended in the doCompress stage.
		endByte := b[len(b)-1]
		padded, err := bytesx.BytesPadPKCS7(b[:len(b)-1], int(blockSize))
		if err != nil {
			return nil, err
		}
		padded[len(padded)-1] = endByte
		return padded, nil
	}
	padded, err := bytesx.BytesPadPKCS7(b, int(blockSize))
	if err != nil {
		return nil, err
	}
	return padded, nil
}

// prependPacketID returns the original buffer with the passed packetID
// concatenated at the beginning.
func prependPacketID(p model.PacketID, buf []byte) []byte {
	newbuf := &bytes.Buffer{}
	packetID := make([]byte, 4)
	binary.BigEndian.PutUint32(packetID, uint32(p))
	newbuf.Write(packetID[:])
	newbuf.Write(buf)
	return newbuf.Bytes()
}

// opcodeAndKeyHeader returns the header byte encoding the opcode and keyID (3 upper
// and 5 lower bits, respectively)
func opcodeAndKeyHeader(session *session.Manager) byte {
	return byte((byte(model.P_DATA_V2) << 3) | (byte(session.CurrentKeyID()) & 0x07))
}
