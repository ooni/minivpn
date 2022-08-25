package vpn

//
// Catalog of the events that can be emitted, so that users of the library can
// observe progress of the client's bootstrap.
//

const (
	EventReady = iota
	EventDialDone
	EventHandshake
	EventReset
	EventTLSConn
	EventTLSHandshake
	EventTLSHandshakeDone
	EventDataInitDone
	EventHandshakeDone
)
