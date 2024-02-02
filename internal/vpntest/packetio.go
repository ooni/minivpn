package vpntest

import (
	"slices"
	"time"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/model"
)

// PacketWriter writes packets into a channel.
type PacketWriter struct {
	// A channel where to write packets to.
	ch chan<- *model.Packet

	// LocalSessionID is needed to produce packets that pass sanity checks.
	LocalSessionID model.SessionID
}

// NewPacketWriter creates a new PacketWriter.
func NewPacketWriter(ch chan<- *model.Packet) *PacketWriter {
	return &PacketWriter{ch: ch}
}

// WriteSequence writes the passed packet sequence (in their string representation)
// to the configured channel. It will wait the specified interval between one packet and the next.
func (pw *PacketWriter) WriteSequence(seq []string) {
	for _, testStr := range seq {
		testPkt, err := NewTestPacketFromString(testStr)
		if err != nil {
			panic("PacketWriter: error reading test sequence:" + err.Error())
		}

		p := &model.Packet{
			Opcode:          testPkt.Opcode,
			RemoteSessionID: pw.LocalSessionID,
			ID:              model.PacketID(testPkt.ID),
		}
		pw.ch <- p
		time.Sleep(testPkt.IAT)
	}
}

// LoggedPacket is a trace of a received packet.
type LoggedPacket struct {
	ID     int
	Opcode model.Opcode
	At     time.Duration
}

// PacketLog is a sequence of LoggedPacket.
type PacketLog []*LoggedPacket

// IDSequence returns a sequence of int from the logged packets.
func (l PacketLog) IDSequence() []int {
	ids := make([]int, 0)
	for _, p := range l {
		ids = append(ids, int(p.ID))
	}
	return ids
}

// PacketReader reads packets from a channel.
type PacketReader struct {
	ch  <-chan *model.Packet
	log []*LoggedPacket
}

// NewPacketReader creates a new PacketReader.
func NewPacketReader(ch <-chan *model.Packet) *PacketReader {
	return &PacketReader{ch: ch}
}

// WaitForSequence loops reading from the internal channel until the logged
// sequence matches the len of the expected sequence; it returns
// true if the obtained packet ID sequence matches the expected one.
func (pr *PacketReader) WaitForSequence(seq []int, start time.Time) bool {
	logged := make([]*LoggedPacket, 0)
	for {
		// have we read enough packets to call it a day?
		if len(logged) >= len(seq) {
			break
		}
		// no, so let's keep reading until the test runner kills us
		pkt := <-pr.ch
		logged = append(
			logged,
			&LoggedPacket{
				ID:     int(pkt.ID),
				Opcode: pkt.Opcode,
				At:     time.Since(start),
			})
		log.Debugf("got packet: %v", pkt.ID)
	}
	pr.log = logged
	return slices.Equal(seq, PacketLog(logged).IDSequence())
}

// Log returns the log of the received packets.
func (pr *PacketReader) Log() PacketLog {
	return PacketLog(pr.log)
}
