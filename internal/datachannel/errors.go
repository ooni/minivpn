package datachannel

import "errors"

var (
	errDataChannelKey = errors.New("bad key")
	errBadCompression = errors.New("bad compression")
	ErrReplayAttack   = errors.New("replay attack")
	ErrBadHMAC        = errors.New("bad hmac")
	ErrInitError      = errors.New("improperly initialized")
	ErrExpiredKey     = errors.New("key is expired")

	// ErrInvalidKeySize means that the key size is invalid.
	ErrInvalidKeySize = errors.New("invalid key size")

	// ErrUnsupportedCipher indicates we don't support the desired cipher.
	ErrUnsupportedCipher = errors.New("unsupported cipher")

	// ErrUnsupportedMode indicates that the mode is not uspported.
	ErrUnsupportedMode = errors.New("unsupported mode")

	// ErrBadInput indicates invalid inputs to encrypt/decrypt functions.
	ErrBadInput = errors.New("bad input")

	ErrSerialization = errors.New("cannot create packet")
	ErrCannotEncrypt = errors.New("cannot encrypt")
	ErrCannotDecrypt = errors.New("cannot decrypt")
)
