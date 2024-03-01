package vpntest

import "testing"

func AssertPanic(t *testing.T, f func()) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected code to panic")
		}
	}()
	f()
}
