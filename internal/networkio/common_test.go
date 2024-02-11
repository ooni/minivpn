package networkio

import (
	"context"
	"errors"
	"net"

	"github.com/ooni/minivpn/internal/vpntest"
)

type mockedConn struct {
	conn    *vpntest.Conn
	dataIn  [][]byte
	dataOut [][]byte
}

func (mc *mockedConn) NetworkReads() [][]byte {
	return mc.dataOut
}

func (mc *mockedConn) NetworkWrites() [][]byte {
	return mc.dataIn
}

func newDialer(underlying *mockedConn) *vpntest.Dialer {
	dialer := &vpntest.Dialer{
		MockDialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return underlying.conn, nil
		},
	}
	return dialer
}

func newMockedConn(network string, dataIn, dataOut [][]byte) *mockedConn {
	conn := &mockedConn{
		dataIn:  dataIn,
		dataOut: dataOut,
	}
	conn.conn = &vpntest.Conn{
		MockLocalAddr: func() net.Addr {
			addr := &vpntest.Addr{
				MockString:  func() string { return "1.2.3.4" },
				MockNetwork: func() string { return network },
			}
			return addr
		},
		MockRead: func(b []byte) (int, error) {
			if len(conn.dataOut) > 0 {
				copy(b[:], conn.dataOut[0])
				ln := len(conn.dataOut[0])
				conn.dataOut = conn.dataOut[1:]
				return ln, nil
			}
			return 0, errors.New("EOF")
		},
		MockWrite: func(b []byte) (int, error) {
			conn.dataIn = append(conn.dataIn, b)
			return len(b), nil
		},
	}
	return conn
}
