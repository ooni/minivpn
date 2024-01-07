package datachannel

import "errors"

var (
	errDataChannel    = errors.New("datachannel error")
	errDataChannelKey = errors.New("bad key")
	errBadCompression = errors.New("bad compression")
	errReplayAttack   = errors.New("replay attack")
	errBadHMAC        = errors.New("bad hmac")
	errInitError      = errors.New("improperly initialized")
	errExpiredKey     = errors.New("key is expired")

	// errInvalidKeySize means that the key size is invalid.
	errInvalidKeySize = errors.New("invalid key size")

	// errUnsupportedCipher indicates we don't support the desired cipher.
	errUnsupportedCipher = errors.New("unsupported cipher")

	// errUnsupportedMode indicates that the mode is not uspported.
	errUnsupportedMode = errors.New("unsupported mode")

	// errBadInput indicates invalid inputs to encrypt/decrypt functions.
	errBadInput = errors.New("bad input")

	ErrCannotEncrypt = errors.New("cannot encrypt")
	ErrCannotDecrypt = errors.New("cannot decrypt")
)
