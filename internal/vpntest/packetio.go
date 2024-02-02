package vpntest

import (
	"slices"
	"time"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/model"
)

// PacketWriter is a service that writes packets into a channel.
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

	At time.Duration
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
	got []*LoggedPacket
}

// NewPacketReader creates a new PacketReader.
func NewPacketReader(ch <-chan *model.Packet) *PacketReader {
	return &PacketReader{ch: ch}
}

// WaitForSequence blocks forever reading from the internal channel until the obtained
// sequence matches the len of the expected; it stores the received sequence and then returns
// true if the obtained packet ID sequence matches the expected one.
func (pr *PacketReader) WaitForSequence(seq []int, start time.Time) bool {
	got := make([]*LoggedPacket, 0)
	for {
		// have we read enough packets to call it a day?
		if len(got) >= len(seq) {
			break
		}
		// no, so let's keep reading until the test runner kills us
		pkt := <-pr.ch
		got = append(
			got,
			&LoggedPacket{
				ID:     int(pkt.ID),
				Opcode: pkt.Opcode,
				At:     time.Since(start),
			})
		log.Debugf("got packet: %v", pkt.ID)
	}
	pr.got = got
	return slices.Equal(seq, PacketLog(got).IDSequence())
}

// ReceivedSequence returns the log of the received sequence.
func (pr *PacketReader) ReceivedSequence() []*LoggedPacket {
	return pr.got
}
