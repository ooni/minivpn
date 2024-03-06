package model

// NegotiationState is the state of the session negotiation.
type NegotiationState int

const (
	// S_ERROR means there was some form of protocol error.
	S_ERROR = NegotiationState(iota) - 1

	// S_UNDEF is the undefined state.
	S_UNDEF

	// S_INITIAL means we're ready to begin the three-way handshake.
	S_INITIAL

	// S_PRE_START means we're waiting for acknowledgment from the remote.
	S_PRE_START

	// S_START means we've done the three-way handshake.
	S_START

	// S_SENT_KEY means we have sent the local part of the key_source2 random material.
	S_SENT_KEY

	// S_GOT_KEY means we have got the remote part of key_source2.
	S_GOT_KEY

	// S_ACTIVE means the control channel was established.
	S_ACTIVE

	// S_GENERATED_KEYS means the data channel keys have been generated.
	S_GENERATED_KEYS
)

// String maps a [SessionNegotiationState] to a string.
func (sns NegotiationState) String() string {
	switch sns {
	case S_UNDEF:
		return "S_UNDEF"
	case S_INITIAL:
		return "S_INITIAL"
	case S_PRE_START:
		return "S_PRE_START"
	case S_START:
		return "S_START"
	case S_SENT_KEY:
		return "S_SENT_KEY"
	case S_GOT_KEY:
		return "S_GOT_KEY"
	case S_ACTIVE:
		return "S_ACTIVE"
	case S_GENERATED_KEYS:
		return "S_GENERATED_KEYS"
	case S_ERROR:
		return "S_ERROR"
	default:
		return "S_INVALID"
	}
}
