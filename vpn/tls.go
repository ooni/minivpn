package vpn

import (
	"bytes"
	"log"
	"net"
	"sync"
	"time"
)

// this wrapper allows TLS Handshake to send its records
// as part of one openvpn CONTROL_V1 packet

type controlWrapper struct {
	control   *control
	bufReader *bytes.Buffer
	mu        sync.Mutex
}

func (cw controlWrapper) Write(b []byte) (n int, err error) {
	return cw.control.sendControlV1(b)
}

func (cw controlWrapper) Read(b []byte) (int, error) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	var data []byte
	if len(b) == 0 {
		return 0, nil
	}
	// quick hack: w/o this wait, we arrive here while some other data
	// is being processed going to the tlsIn queue. use a proper sync
	// primitive instead! -- interestingly, this one wait seems to be needed
	// even with the delayed out-of-order hack below.
	time.Sleep(50 * time.Millisecond)

	if len(cw.control.tlsIn) != 0 {
		var p []byte
		p = <-cw.control.tlsIn
		cw.bufReader.Write(p)
		return cw.bufReader.Read(b)
	}
	go func() {
		buf := make([]byte, len(b))
		numBytes, _ := cw.control.conn.Read(buf)
		data = buf[:numBytes]

		if numBytes == 0 {
			return
		}

		op := data[0] >> 3
		if op == byte(P_ACK_V1) {
			// XXX might want to do something with this ACK
			log.Println("Received ACK")
			return
		}
		if isDataOpcode(op) {
			cw.control.dataQueue <- data
			return
		}
		if op != byte(P_CONTROL_V1) {
			// FIXME need to pass this to data channel to decrypt...
			log.Printf("Received unknown opcode: %v\n", op)
			log.Printf("len: %d\n", len(data))
			log.Printf("data: %v\n", data)
			log.Fatal("Unknown Opcode")
		}

		// log.Printf("TLS data in (%d bytes) \n", len(data))

		pid, _, payload := cw.control.readControl(data)
		cw.control.sendAck(pid)
		// same hack that in ACK'ing on the control channel.
		// instead of the ugly hack of waiting, it'd be more elegant to
		// find the right sync primitive to avoid this.
		// part of the problem is that I don't quite understand why some times
		// something enters the tls queue that is not what's expected for a tls
		// record.
		if int(pid)-cw.control.lastAck > 1 {
			go func() {
				log.Println("DEBUG delay in TLS buffer...")
				time.Sleep(time.Second)
				cw.control.tlsIn <- payload
			}()
		} else {
			cw.control.tlsIn <- payload
		}
	}()
	return 0, nil
}

func (cw controlWrapper) LocalAddr() net.Addr {
	return cw.control.conn.LocalAddr()
}

func (cw controlWrapper) RemoteAddr() net.Addr {
	return cw.control.conn.RemoteAddr()
}

func (cw controlWrapper) SetDeadline(t time.Time) error {
	return cw.control.conn.SetDeadline(t)
}

func (cw controlWrapper) SetReadDeadline(t time.Time) error {
	return cw.control.conn.SetReadDeadline(t)
}

func (cw controlWrapper) SetWriteDeadline(t time.Time) error {
	return cw.control.conn.SetWriteDeadline(t)
}

func (cw controlWrapper) Close() error {
	return cw.control.conn.Close()
}
