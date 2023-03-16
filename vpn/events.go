package vpn

//
// Catalog of the events that can be emitted, so that users of the library can
// observe progress of the client's bootstrap.
//

const (
	// Be very careful when altering the order of these event; other libraries
	// might be trusting their values, so please release a new version and
	// document the changes in that case.
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
