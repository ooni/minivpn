package vpn

var (
	// ErrBadCA is returned when the CA file cannot be found or is not valid.
	ErrBadCA = "bad ca conf"
	// ErrBadKeypair is returned when the key or cert file cannot be found or is not valid.
	ErrBadKeypair = "bad keypair conf"
	// ErrBadHandshake is returned when the OpenVPN handshake failed.
	ErrBadHandshake = "handshake failure"
	// ErrDialError
	ErrDialError = "dial error"
)
