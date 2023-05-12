package datachannel

import "errors"

var (
	errDataChannelKey = errors.New("bad key")
	errBadCompression = errors.New("bad compression")
	errReplayAttack   = errors.New("replay attack")
	errBadHMAC        = errors.New("bad hmac")
	errInitError      = errors.New("improperly initialized")
	errRandomBytes    = errors.New("error generating random bytes")
	errExpiredKey     = errors.New("key is expired")
)
