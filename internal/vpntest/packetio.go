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

	// LocalSessionID is needed to produce incoming packets that pass sanity checks.
	LocalSessionID model.SessionID

	// RemoteSessionID is needed to produce ACKs.
	RemoteSessionID model.SessionID
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
			RemoteSessionID: pw.RemoteSessionID,
			LocalSessionID:  pw.LocalSessionID,
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
	ACKs   []model.PacketID
	At     time.Duration
}

// newLoggedPacket returns a pointer to LoggedPacket from a real packet and a origin of time.
func newLoggedPacket(p *model.Packet, origin time.Time) *LoggedPacket {
	return &LoggedPacket{
		ID:     int(p.ID),
		Opcode: p.Opcode,
		ACKs:   p.ACKs,
		At:     time.Since(origin),
	}
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

// acks filters the log and returns an array of ids that have been acked
// either as ack packets or as part of the ack array of an outgoing packet.
func (l PacketLog) acks() []int {
	acks := []int{}
	for _, p := range l {
		for _, ack := range p.ACKs {
			acks = append(acks, int(ack))
		}
	}
	return acks
}

// PacketReader reads packets from a channel.
type PacketReader struct {
	ch  <-chan *model.Packet
	log []*LoggedPacket
}

// NewPacketReader creates a new PacketReader.
func NewPacketReader(ch <-chan *model.Packet) *PacketReader {
	logged := make([]*LoggedPacket, 0)
	return &PacketReader{ch: ch, log: logged}
}

// WaitForSequence loops reading from the internal channel until the logged
// sequence matches the len of the expected sequence; it returns
// true if the obtained packet ID sequence matches the expected one.
func (pr *PacketReader) WaitForSequence(seq []int, start time.Time) bool {
	for {
		// have we read enough packets to call it a day?
		if len(pr.log) >= len(seq) {
			break
		}
		// no, so let's keep reading until the test runner kills us
		pkt := <-pr.ch
		pr.log = append(pr.log, newLoggedPacket(pkt, start))
		log.Debugf("got packet: %v", pkt.ID)
	}
	// TODO move the comparison to witness, leave only wait here
	return slices.Equal(seq, PacketLog(pr.log).IDSequence())
}

func (pr *PacketReader) WaitForNumberOfACKs(total int, start time.Time) {
	for {
		// have we read enough acks to call it a day?
		if len(PacketLog(pr.log).acks()) >= total {
			break
		}
		// no, so let's keep reading until the test runner kills us
		pkt := <-pr.ch
		pr.log = append(pr.log, newLoggedPacket(pkt, start))
		log.Debugf("got packet: %v", pkt.ID)
	}
}

// Log returns the log of the received packets.
func (pr *PacketReader) Log() PacketLog {
	return PacketLog(pr.log)
}

// A Witness checks for different conditions over a reader
type Witness struct {
	reader *PacketReader
}

func NewWitness(r *PacketReader) *Witness {
	return &Witness{r}
}

func (w *Witness) Log() PacketLog {
	return w.reader.Log()
}

// VerifyACKs tells the underlying reader to wait for a given number of acks,
// and then checks that we have an ack sequence without holes.
func (w *Witness) VerifyACKs(total int, t time.Time) bool {
	w.reader.WaitForNumberOfACKs(total, t)
	// TODO: compare the range here, no holes
	// TODO: probl. need start idx
	return true
}

func (w *Witness) NumberOfACKs() int {
	return len(w.reader.Log().acks())
}
