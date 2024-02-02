package reliabletransport

const (
	// Capacity for the array of packets that we're tracking at any given moment (outgoing).
	// This is defined by OpenVPN in ssl_pkt.h
	RELIABLE_SEND_BUFFER_SIZE = 6

	// Capacity for the array of packets that we're tracking at any given moment (incoming).
	// This is defined by OpenVPN in ssl_pkt.h
	RELIABLE_RECV_BUFFER_SIZE = 12

	// The maximum numbers of ACKs that we put in an array for an outgoing packet.
	MAX_ACKS_PER_OUTGOING_PACKET = 4

	// How many IDs pending to be acked can we store.
	ACK_SET_CAPACITY = 8

	// Initial timeout for TLS retransmission, in seconds.
	INITIAL_TLS_TIMEOUT_SECONDS = 2

	// Maximum backoff interval, in seconds.
	MAX_BACKOFF_SECONDS = 60

	// Default sender ticker period, in milliseconds.
	SENDER_TICKER_MS = 1000 * 60
)
