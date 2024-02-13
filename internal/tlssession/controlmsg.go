package tlssession

//
// The functions in this file deal with control messages. These control
// messages are sent and received over the TLS session once we've gone one
// established.
//
// The control **channel** below us will deal with serializing and deserializing them,
// what we receive at this stage are the cleartext payloads obtained after decrypting
// an application data TLS record.
//

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ooni/minivpn/internal/bytesx"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
)

// encodeClientControlMessage returns a byte array with the payload for a control channel packet.
// This is the packet that the client sends to the server with the key
// material, local options and credentials (if username+password authentication is used).
func encodeClientControlMessageAsBytes(k *session.KeySource, o *model.OpenVPNOptions) ([]byte, error) {
	opt, err := bytesx.EncodeOptionStringToBytes(o.ServerOptionsString())
	if err != nil {
		return nil, err
	}
	user, err := bytesx.EncodeOptionStringToBytes(string(o.Username))
	if err != nil {
		return nil, err
	}
	pass, err := bytesx.EncodeOptionStringToBytes(string(o.Password))
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	out.Write(controlMessageHeader)
	out.WriteByte(0x02) // key method (2)
	out.Write(k.Bytes())
	out.Write(opt)
	out.Write(user)
	out.Write(pass)

	// we could send IV_PLAT too, but afaik declaring the platform does not
	// make any difference for our purposes.
	rawInfo := fmt.Sprintf("IV_VER=%s\nIV_PROTO=%s\n", ivVer, ivProto)
	peerInfo, _ := bytesx.EncodeOptionStringToBytes(rawInfo)
	out.Write(peerInfo)
	return out.Bytes(), nil
}

// controlMessageHeader is the header prefixed to control messages
var controlMessageHeader = []byte{0x00, 0x00, 0x00, 0x00}

const ivVer = "2.5.5" // OpenVPN version compat that we declare to the server
const ivProto = "2"   // IV_PROTO declared to the server. We need to be sure to enable the peer-id bit to use P_DATA_V2.

// errMissingHeader indicates that we're missing the four-byte all-zero header.
var errMissingHeader = errors.New("missing four-byte all-zero header")

// errInvalidHeader indicates that the header is not a sequence of four zeroed bytes.
var errInvalidHeader = errors.New("expected four-byte all-zero header")

// errBadControlMessage indicates that a control message cannot be parsed.
var errBadControlMessage = errors.New("cannot parse control message")

// errBadKeyMethod indicates we don't support a key method
var errBadKeyMethod = errors.New("unsupported key method")

// parseControlMessage gets a server control message and returns the value for
// the remote key, the server remote options, and an error indicating if the
// operation could not be completed.
func parseServerControlMessage(message []byte) (*session.KeySource, string, error) {
	if len(message) < 4 {
		return nil, "", errMissingHeader
	}
	if !bytes.Equal(message[:4], controlMessageHeader) {
		return nil, "", errInvalidHeader
	}
	// TODO(ainghazal): figure out why 71 here
	if len(message) < 71 {
		return nil, "", fmt.Errorf("%w: bad len from server:%d", errBadControlMessage, len(message))
	}
	keyMethod := message[4]
	if keyMethod != 2 {
		return nil, "", fmt.Errorf("%w: %d", errBadKeyMethod, keyMethod)

	}
	var random1, random2 [32]byte
	// first chunk of random bytes
	copy(random1[:], message[5:37])
	// second chunk of random bytes
	copy(random2[:], message[37:69])

	options, err := bytesx.DecodeOptionStringFromBytes(message[69:])
	if err != nil {
		return nil, "", fmt.Errorf("%w:%s", errBadControlMessage, "bad options string")
	}

	remoteKey := &session.KeySource{
		R1:        random1,
		R2:        random2,
		PreMaster: [48]byte{},
	}
	return remoteKey, options, nil
}

// serverBadAuth indicates that the authentication failed
var serverBadAuth = []byte("AUTH_FAILED")

// serverPushReply is the response for a successful push request
var serverPushReply = []byte("PUSH_REPLY")

// errBadAuth means we could not authenticate
var errBadAuth = errors.New("server says: bad auth")

// errBadServerReply indicates we didn't get one of the few responses we expected
var errBadServerReply = errors.New("bad server reply")

// parseServerPushReply parses the push reply
func parseServerPushReply(logger model.Logger, resp []byte) (*model.TunnelInfo, error) {
	// make sure the server's response contains the expected result
	if bytes.HasPrefix(resp, serverBadAuth) {
		return nil, errBadAuth
	}
	if !bytes.HasPrefix(resp, serverPushReply) {
		return nil, fmt.Errorf("%w:%s", errBadServerReply, "expected push reply")
	}

	// TODO(bassosimone): consider moving the two functions below in this package
	optsMap := model.PushedOptionsAsMap(resp)
	logger.Infof("Server pushed options: %v", optsMap)
	ti := model.NewTunnelInfoFromPushedOptions(optsMap)
	return ti, nil
}
