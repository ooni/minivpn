package vpn

import (
	"net"
	"testing"
)

func Test_newControl(t *testing.T) {
	rnd := "0123456789"

	c, _ := net.Dial("tcp", "127.0.0.1:0")
	ks := &keySource{[]byte(rnd), []byte(rnd), []byte(rnd)}
	o := &Options{}

	ctrl := newControl(c, ks, o)
	if ctrl == nil {
		t.Errorf("ctrl should not be nil")
	}
	err := ctrl.initSession()
	if err != nil {
		t.Errorf("initSession should not fail")
	}
	if len(ctrl.SessionID) == 0 {
		t.Errorf("Local session should be initialized")
	}
}
