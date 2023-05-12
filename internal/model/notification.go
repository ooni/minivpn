package model

const (
	// NotificationReset indicates that a SOFT or HARD reset occurred.
	NotificationReset = 1 << iota
)

// Notification is a notification for a service worker.
type Notification struct {
	// Flags contains flags explaining what happened.
	Flags int64
}
