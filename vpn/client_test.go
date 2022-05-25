package vpn

import (
	"errors"
	"net"
	"reflect"
	"testing"
	"time"
)

// the name is confusing, but we're just getting a generic mocked conn
// that serves as witness of calls
// TODO can copy the mockTLSConn here to avoid confusion with names and
// decouple these tests from those.
func makeTestingClientConn() (*Client, *MockTLSConn) {
	c := makeConnForTransportTest()
	cl := &Client{}
	cl.conn = c
	return cl, c
}

func TestNewClientFromOptions(t *testing.T) {
	randomFn = func(int) ([]byte, error) {
		return []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, nil
	}
	opts := makeTestingOptions("AES-128-GCM", "sha512")
	_ = NewClientFromOptions(opts)

	c := NewClientFromOptions(nil)
	if !reflect.DeepEqual(c, &Client{}) {
		t.Error("Client.NewClientFromOptions(): expected empty client with nil options")
	}
}

// for the tests that test the delegation of methods to the underlying conn we
// can reuse the mock used in transport_test

func TestClient_SetDeadline(t *testing.T) {
	cl, conn := makeTestingClientConn()
	err := cl.SetDeadline(time.Now().Add(time.Second))
	if err != nil {
		t.Errorf("Client.SetDeadline() error = %v, want = nil", err)
	}
	if !conn.setDeadlineCalled {
		t.Error("Client.SetDeadline(): conn.SetDeadline() not called")
	}

}

func TestClient_SetReadDeadline(t *testing.T) {
	cl, conn := makeTestingClientConn()
	err := cl.SetReadDeadline(time.Now().Add(time.Second))
	if err != nil {
		t.Errorf("Client.SetDeadline() error = %v, want = nil", err)
	}
	if !conn.setReadDeadlineCalled {
		t.Error("Client.SetReadDeadline(): conn.SetReadDeadline() not called")
	}
}

func TestClient_SetWriteDeadline(t *testing.T) {
	cl, conn := makeTestingClientConn()
	err := cl.SetWriteDeadline(time.Now().Add(time.Second))
	if err != nil {
		t.Errorf("Client.SetWriteDeadline() error = %v, want = nil", err)
	}
	if !conn.setWriteDeadlineCalled {
		t.Error("Client.SetWriteDeadline(): conn.SetWriteReadDeadline() not called")
	}
}

func TestClient_Close(t *testing.T) {
	cl, conn := makeTestingClientConn()
	err := cl.Close()
	if err != nil {
		t.Errorf("Client.Close() error = %v, want = nil", err)
	}
	if !conn.closedCalled {
		t.Error("Client.Close(): conn.Close() not called")
	}
}

func TestClient_DialFailsWithBadOptions(t *testing.T) {
	c := &Client{}
	_, err := c.Dial()
	wantErr := errBadInput
	if !errors.Is(err, wantErr) {
		t.Error("Client.Dial(): should fail with nil options")
	}

	c = &Client{
		Opts: &Options{
			Proto: 3,
		},
	}
	_, err = c.Dial()
	wantErr = errBadInput
	if !errors.Is(err, wantErr) {
		t.Error("Client.Dial(): should fail with bad proto")
	}

	badDialFn := func(string, string) (net.Conn, error) {
		return nil, errors.New("weird error")
	}
	c = &Client{
		Opts: &Options{
			Proto: TCPMode,
		},
		DialFn: badDialFn,
	}
	_, err = c.Dial()
	wantErr = ErrDialError
	if !errors.Is(err, wantErr) {
		t.Errorf("Client.Dial(): should fail with ErrDialError, err = %v", err)
	}
}
