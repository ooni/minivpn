package tlssession

import (
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/runtimex"
)

func Test_tlsBio(t *testing.T) {
	t.Run("can close tlsbio more than once", func(t *testing.T) {
		up := make(chan []byte, 10)
		down := make(chan []byte, 10)
		tls := newTLSBio(log.Log, up, down)
		tls.Close()
		tls.Close()
	})

	t.Run("read less than in buffer", func(t *testing.T) {
		up := make(chan []byte, 10)
		down := make(chan []byte, 10)
		up <- []byte("abcd")
		tls := newTLSBio(log.Log, up, down)
		buf := []byte{1}
		n, err := tls.Read(buf)
		if err != nil {
			t.Error("expected error nil")
		}
		if n != 1 {
			t.Error("expected 1 byte read")
		}
		if string(buf) != "a" {
			t.Error("expected to read 'a'")
		}
	})

	t.Run("write sends bytes down", func(t *testing.T) {
		up := make(chan []byte, 10)
		down := make(chan []byte, 10)
		up <- []byte("abcd")
		tls := newTLSBio(log.Log, up, down)
		buf := []byte("abcd")
		n, err := tls.Write(buf)
		if err != nil {
			t.Error("should not fail")
		}
		if n != 4 {
			t.Error("expected 4 bytes written")
		}
		got := <-down
		if string(got) != "abcd" {
			t.Errorf("did not write what expected")
		}
	})

	t.Run("exercise net.Conn implementation", func(t *testing.T) {
		up := make(chan []byte, 10)
		down := make(chan []byte, 10)
		tls := newTLSBio(log.Log, up, down)
		runtimex.Assert(tls.LocalAddr().Network() == "tlsBioAddr", "bad network")
		runtimex.Assert(tls.LocalAddr().String() == "tlsBioAddr", "bad addr")
		tls.RemoteAddr()
		tls.SetReadDeadline(time.Now())
		tls.SetWriteDeadline(time.Now())
		tls.SetDeadline(time.Now())
	})
}
