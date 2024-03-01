package networkio

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/vpntest"
)

func Test_TCPLikeConn(t *testing.T) {
	t.Run("A tcp-like conn implements the openvpn size framing", func(t *testing.T) {
		dataIn := make([][]byte, 0)
		dataOut := make([][]byte, 0)
		// write size
		dataOut = append(dataOut, []byte{0, 8})
		// write payload
		want := []byte("deadbeef")
		dataOut = append(dataOut, want)

		underlying := newMockedConn("tcp", dataIn, dataOut)
		testDialer := newDialer(underlying)
		dialer := NewDialer(log.Log, testDialer)
		framingConn, err := dialer.DialContext(context.Background(), "tcp", "1.1.1.1")

		if err != nil {
			t.Errorf("should not error getting a framingConn")
		}
		got, err := framingConn.ReadRawPacket()
		if err != nil {
			t.Errorf("should not error: err = %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("got = %v, want = %v", got, want)
		}

		written := []byte("ingirumimusnocteetconsumimurigni")
		framingConn.WriteRawPacket(written)
		gotWritten := underlying.NetworkWrites()
		if !bytes.Equal(gotWritten[0], append([]byte{0, byte(len(written))}, written...)) {
			t.Errorf("got = %v, want = %v", gotWritten, written)
		}
	})
}

func Test_UDPLikeConn(t *testing.T) {
	t.Run("A udp-like conn returns the packets directly", func(t *testing.T) {
		dataIn := make([][]byte, 0)
		dataOut := make([][]byte, 0)
		// write payload
		want := []byte("deadbeef")
		dataOut = append(dataOut, want)

		underlying := newMockedConn("udp", dataIn, dataOut)
		testDialer := newDialer(underlying)
		dialer := NewDialer(log.Log, testDialer)
		framingConn, err := dialer.DialContext(context.Background(), "udp", "1.1.1.1")
		if err != nil {
			t.Errorf("should not error getting a framingConn")
		}
		got, err := framingConn.ReadRawPacket()
		if err != nil {
			t.Errorf("should not error: err = %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("got = %v, want = %v", got, want)
		}
		written := []byte("ingirumimusnocteetconsumimurigni")
		framingConn.WriteRawPacket(written)
		gotWritten := underlying.NetworkWrites()
		if !bytes.Equal(gotWritten[0], written) {
			t.Errorf("got = %v, want = %v", gotWritten, written)
		}
	})
}

func Test_CloseOnceConn(t *testing.T) {
	t.Run("A conn can be closed more than once", func(t *testing.T) {
		ctr := 0
		testDialer := &vpntest.Dialer{
			MockDialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				conn := &vpntest.Conn{
					MockClose: func() error {
						ctr++
						return nil
					},
					MockLocalAddr: func() net.Addr {
						addr := &vpntest.Addr{
							MockString:  func() string { return "1.2.3.4" },
							MockNetwork: func() string { return network },
						}
						return addr
					},
				}
				return conn, nil
			},
		}

		dialer := NewDialer(log.Log, testDialer)
		framingConn, err := dialer.DialContext(context.Background(), "tcp", "1.1.1.1")
		if err != nil {
			t.Errorf("should not error getting a framingConn")
		}
		framingConn.Close()
		framingConn.Close()
		if ctr != 1 {
			t.Errorf("close function should be called only once")
		}
	})
}
