package vpntest

import (
	"slices"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/bytesx"
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

func (pw *PacketWriter) WritePacketWithID(i int) {
	p := &model.Packet{
		Opcode:          model.P_CONTROL_V1,
		RemoteSessionID: pw.RemoteSessionID,
		LocalSessionID:  pw.LocalSessionID,
		ID:              model.PacketID(i),
	}
	pw.ch <- p
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

// ACKs filters the log and returns an array of unique ids that have been acked
// either as ack packets or as part of the ack array of an outgoing packet.
func (l PacketLog) ACKs() []int {
	acks := []int{}
	for _, p := range l {
		for _, ack := range p.ACKs {
			a := int(ack)
			if !contains(acks, a) {
				acks = append(acks, a)
			}
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
		if len(PacketLog(pr.log).ACKs()) >= total {
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
// returns true if we have the same number of acks.
func (w *Witness) VerifyNumberOfACKs(start, total int, t time.Time) bool {
	w.reader.WaitForNumberOfACKs(total, t)
	return len(w.Log().ACKs()) == total
}

// contains check if the element is in the slice. this is expensive, but it's only
// for tests and the alternative is to make ackSet public.
func contains(slice []int, target int) bool {
	for _, item := range slice {
		if item == target {
			return true
		}
	}
	return false
}

// PacketRelay receives and sends packets.
type PacketRelay struct {
	dataIn  <-chan *model.Packet
	dataOut chan<- *model.Packet

	reader *PacketReader

	// local counter for packet id
	outPacketID int

	// localSessionID is needed to produce incoming packets that pass sanity checks.
	localSessionID model.SessionID

	// RemoteSessionID is needed to produce ACKs.
	RemoteSessionID model.SessionID

	closeOnce sync.Once
	mu        sync.Mutex // Guards cancel
	cancel    chan struct{}
}

func NewPacketRelay(dataIn <-chan *model.Packet, dataOut chan<- *model.Packet) *PacketRelay {
	b, err := bytesx.GenRandomBytes(8)
	if err != nil {
		panic(err)
	}
	return &PacketRelay{
		dataIn:         dataIn,
		dataOut:        dataOut,
		reader:         &PacketReader{},
		outPacketID:    0,
		localSessionID: model.SessionID(b),

		mu:     sync.Mutex{},
		cancel: make(chan struct{}),
	}
}

// Log returns the packet log this relay received.
func (pr *PacketRelay) Log() PacketLog {
	if pr.reader == nil {
		return PacketLog{}
	}
	return pr.reader.Log()
}

// RelayWithLossess will relay incoming packets according to a vector of packetID that must be dropped.
// To specify repeated losses for a packet ID, the vector of losses must repeat the id several times.
func (pr *PacketRelay) RelayWithLosses(losses []int) {
	ctr := makeLossMap(losses)
	for {
		select {
		case <-pr.cancel:
			return
		case pkt := <-pr.dataIn:
			id := int(pkt.ID)
			cnt, ok := ctr[id]
			if !ok || cnt <= 0 {
				log.Debugf("relay packet: %v", id)
				pr.WritePacketWithID(id)
			} else {
				log.Debugf("drop packet: %v", id)
			}
			ctr[id] -= 1
		}
	}
}

func (pr *PacketRelay) WritePacketWithID(i int) {
	p := &model.Packet{
		Opcode:          model.P_CONTROL_V1,
		RemoteSessionID: pr.RemoteSessionID,
		LocalSessionID:  pr.localSessionID,
		ID:              model.PacketID(i),
	}
	pr.dataOut <- p
}

func (pr *PacketRelay) WritePacketWithPayload(payload []byte) {
	p := &model.Packet{
		Opcode:          model.P_CONTROL_V1,
		RemoteSessionID: pr.RemoteSessionID,
		LocalSessionID:  pr.localSessionID,
		ID:              pr.packetID(),
		Payload:         payload,
	}
	pr.dataOut <- p
}

func (pr *PacketRelay) Stop() {
	pr.closeOnce.Do(func() {
		close(pr.cancel)
	})

}

func (pr *PacketRelay) packetID() model.PacketID {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	id := model.PacketID(pr.outPacketID)
	pr.outPacketID += 1
	return id
}

// makeLossMap returns a map from packet IDs to int. The value
// of the map represent how many times we have to observe a given packet ID
// before relaying it.
func makeLossMap(l []int) map[int]int {
	lc := make(map[int]int)
	for _, i := range l {
		_, ok := lc[i]
		if !ok {
			lc[i] = 1
		} else {
			lc[i] += 1
		}
	}
	return lc
}
