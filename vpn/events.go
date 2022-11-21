package vpn

//
// Catalog of the events that can be emitted, so that users of the library can
// observe progress of the client's bootstrap.
//

// The events to be emitted. This is treated as an uint8, so if we ever go past
// 255 events we need to accomodate the data type.
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
