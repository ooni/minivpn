package datachannel

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ooni/minivpn/internal/bytesx"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/runtimex"
	"github.com/ooni/minivpn/internal/session"
)

func decodeEncryptedPayloadAEAD(log model.Logger, buf []byte, session *session.Manager, state *dataChannelState) (*encryptedData, error) {
	//   P_DATA_V2 GCM data channel crypto format
	//   48000001 00000005 7e7046bd 444a7e28 cc6387b1 64a4d6c1 380275a...
	//   [ OP32 ] [seq # ] [             auth tag            ] [ payload ... ]
	//   - means authenticated -    * means encrypted *
	//   [ - opcode/peer-id - ] [ - packet ID - ] [ TAG ] [ * packet payload * ]

	// preconditions

	if len(buf) == 0 || len(buf) < 20 {
		return nil, fmt.Errorf("too short: %d bytes", len(buf))
	}
	if len(state.hmacKeyRemote) < 8 {
		return nil, fmt.Errorf("bad remote hmac")
	}
	remoteHMAC := state.hmacKeyRemote[:8]
	packet_id := buf[:4]

	headers := &bytes.Buffer{}
	headers.WriteByte(opcodeAndKeyHeader(session))
	bytesx.WriteUint24(headers, uint32(session.TunnelInfo().PeerID))
	headers.Write(packet_id)

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
		aead:       headers.Bytes(),
	}
	return encrypted, nil
}

var errCannotDecode = errors.New("cannot decode")

func decodeEncryptedPayloadNonAEAD(log model.Logger, buf []byte, session *session.Manager, state *dataChannelState) (*encryptedData, error) {
	runtimex.Assert(state != nil, "passed nil state")
	runtimex.Assert(state.dataCipher != nil, "data cipher not initialized")

	hashSize := uint8(state.hmacRemote.Size())
	blockSize := state.dataCipher.blockSize()

	minLen := hashSize + blockSize

	if len(buf) < int(minLen) {
		return &encryptedData{}, fmt.Errorf("%w: too short (%d bytes)", errCannotDecode, len(buf))
	}

	receivedHMAC := buf[:hashSize]
	iv := buf[hashSize : hashSize+blockSize]
	cipherText := buf[hashSize+blockSize:]

	state.hmacRemote.Reset()
	state.hmacRemote.Write(iv)
	state.hmacRemote.Write(cipherText)
	computedHMAC := state.hmacRemote.Sum(nil)

	if !hmac.Equal(computedHMAC, receivedHMAC) {
		log.Warnf("expected: %x, got: %x", computedHMAC, receivedHMAC)
		return &encryptedData{}, fmt.Errorf("%w: %s", ErrCannotDecrypt, errBadHMAC)
	}

	encrypted := &encryptedData{
		iv:         iv,
		ciphertext: cipherText,
		aead:       []byte{}, // no AEAD data in this mode, leaving it empty to satisfy common interface
	}
	return encrypted, nil
}

// maybeDecompress de-serializes the data from the payload according to the framing
// given by different compression methods. only the different no-compression
// modes are supported at the moment, so no real decompression is done. It
// returns a byte array, and an error if the operation could not be completed
// successfully.
func maybeDecompress(b []byte, st *dataChannelState, opt *model.OpenVPNOptions) ([]byte, error) {
	if st == nil || st.dataCipher == nil {
		return []byte{}, fmt.Errorf("%w:%s", errBadInput, "bad state")
	}
	if opt == nil {
		return []byte{}, fmt.Errorf("%w:%s", errBadInput, "bad options")
	}

	var compr byte // compression type
	var payload []byte

	// TODO(ainghazal): have two different decompress implementations
	// instead of this switch
	switch st.dataCipher.isAEAD() {
	case true:
		switch opt.Compress {
		case model.CompressionStub, model.CompressionLZONo:
			// these are deprecated in openvpn 2.5.x
			compr = b[0]
			payload = b[1:]
		default:
			compr = 0x00
			payload = b[:]
		}
	default: // non-aead
		remotePacketID := model.PacketID(binary.BigEndian.Uint32(b[:4]))
		lastKnownRemote, err := st.RemotePacketID()
		if err != nil {
			return payload, err
		}
		if remotePacketID <= lastKnownRemote {
			return []byte{}, errReplayAttack
		}
		st.SetRemotePacketID(remotePacketID)

		switch opt.Compress {
		case model.CompressionStub, model.CompressionLZONo:
			compr = b[4]
			payload = b[5:]
		default:
			compr = 0x00
			payload = b[4:]
		}
	}

	switch compr {
	case 0xfb:
		// compression stub swap:
		// we get the last byte and replace the compression byte
		// these are deprecated in openvpn 2.5.x
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
