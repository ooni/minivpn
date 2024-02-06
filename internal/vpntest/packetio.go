package vpntest

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
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

	payload           string
	packetPayloadSize int
}

// NewPacketWriter creates a new PacketWriter.
func NewPacketWriter(ch chan<- *model.Packet) *PacketWriter {
	return &PacketWriter{ch: ch}
}

// WriteSequence writes the passed packet sequence (in their string representation)
// to the configured channel. It will wait the specified interval between one packet and the next.
// The input sequence strings will be expanded for range notation, as in [1..10]
func (pw *PacketWriter) WriteSequence(seq []string) {
	for _, expr := range seq {
		for _, item := range maybeExpand(expr) {
			pw.writeSequenceItem(item)
		}
	}
}

// possibly expand a input sequence in range notation for the packet ids [1..10]
func maybeExpand(input string) []string {
	fmt.Println("maybe expand")
	items := []string{}
	pattern := `^\[(\d+)\.\.(\d+)\] (.+)`
	regexpPattern := regexp.MustCompile(pattern)
	matches := regexpPattern.FindStringSubmatch(input)
	if len(matches) != 4 {
		// not a range, return the single element
		items = append(items, input)
		return items
	}

	fmt.Println("len matches", len(matches))

	// extract beginning and end of the range
	fromStr := matches[1]
	toStr := matches[2]
	body := matches[3]

	// convert to int (from/to )
	from, err := strconv.Atoi(fromStr)
	if err != nil {
		panic(err)
	}

	to, err := strconv.Atoi(toStr)
	if err != nil {
		panic(err)
	}

	// return the expanded id range
	for i := from; i <= to; i++ {
		items = append(items, fmt.Sprintf("[%d] %s", i, body))
	}
	return items
}

func (pw *PacketWriter) writeSequenceItem(item string) {
	testPkt, err := NewTestPacketFromString(item)
	if err != nil {
		panic("PacketWriter: error reading test sequence:" + err.Error())
	}
	p := &model.Packet{
		Opcode:          testPkt.Opcode,
		RemoteSessionID: pw.RemoteSessionID,
		LocalSessionID:  pw.LocalSessionID,
		ID:              model.PacketID(testPkt.ID),
	}
	if len(pw.payload) > 0 {
		var payload, rest string
		size := pw.packetPayloadSize
		if len(pw.payload) < size {
			payload = pw.payload
			pw.payload = ""
		} else {
			payload, rest = pw.payload[:size], pw.payload[size:]
			pw.payload = rest
		}
		p.Payload = []byte(payload)
	}
	pw.ch <- p
	time.Sleep(testPkt.IAT)
}

// WriteSequenceWithFixed payload will write packets according to the sequence specified in seq,
// but will sequentially pick the payload from the passed payload string, in increments defined by size.
func (pw *PacketWriter) WriteSequenceWithFixedPayload(seq []string, payload string, size int) {
	pw.payload = payload
	pw.packetPayloadSize = 3
	pw.WriteSequence(seq)
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
	ch      <-chan *model.Packet
	log     []*LoggedPacket
	payload []byte
}

// NewPacketReader creates a new PacketReader.
func NewPacketReader(ch <-chan *model.Packet) *PacketReader {
	logged := make([]*LoggedPacket, 0)
	return &PacketReader{ch: ch, log: logged}
}

func (pr *PacketReader) Payload() string {
	return string(pr.payload)
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
		pr.appendOneIncomingPacket(start)
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
		pr.appendOneIncomingPacket(start)
	}
}

func (pr *PacketReader) WaitForOrderedPayloadLen(total int, start time.Time) {
	for {
		// have we read enough packets to call it a day?
		if len(pr.payload) >= total {
			break
		}
		// no, so let's keep reading until the test runner kills us
		pr.appendOneIncomingPacket(start)
	}
}

func (pr *PacketReader) appendOneIncomingPacket(t0 time.Time) {
	pkt := <-pr.ch
	pr.log = append(pr.log, newLoggedPacket(pkt, t0))
	if pkt.Payload != nil {
		pr.payload = append(pr.payload, pkt.Payload...)
	}
	log.Debugf("got packet: %v (%d bytes)", pkt.ID, len(pkt.Payload))
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

func NewWitnessFromChannel(ch <-chan *model.Packet) *Witness {
	return NewWitness(NewPacketReader(ch))

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

func (w *Witness) VerifyOrderedPayload(payload string, t time.Time) bool {
	w.reader.WaitForOrderedPayloadLen(len(payload), t)
	return w.reader.Payload() == payload
}

func (w *Witness) Payload() string {
	return w.reader.Payload()
}

// contains checks if the element is in the slice. this is expensive, but it's only
// for tests and the alternative is to make ackSet public.
func contains(slice []int, target int) bool {
	for _, item := range slice {
		if item == target {
			return true
		}
	}
	return false
}

// PacketRelay sends any received packet, without modifications.
type PacketRelay struct {
	dataIn  <-chan *model.Packet
	dataOut chan<- *model.Packet

	closeOnce sync.Once
	mu        sync.Mutex // Guards cancel
	cancel    chan struct{}
}

func NewPacketRelay(dataIn <-chan *model.Packet, dataOut chan<- *model.Packet) *PacketRelay {
	return &PacketRelay{
		dataIn:  dataIn,
		dataOut: dataOut,

		mu:     sync.Mutex{},
		cancel: make(chan struct{}),
	}
}

// RelayWithLossess will relay incoming packets according to a vector of packetID that must be dropped.
// To specify repeated losses for a packet ID, the vector of losses must repeat the id several times.
func (pr *PacketRelay) RelayWithLosses(losses []int) {
	ctr := makeLossMap(losses)
	for {
		select {
		case <-pr.cancel:
			return
		case p := <-pr.dataIn:
			id := int(p.ID)
			cnt, ok := ctr[id]
			if !ok || cnt <= 0 {
				// not on the loss map, or we already saw the packet enough times
				log.Debugf("relay packet: %v (%s)", id, string(p.Payload))
				pr.dataOut <- p
			} else {
				log.Debugf("relay: drop packet: %v", id)
			}
			// decrement the counter for this packet ID
			ctr[id] -= 1
		}
	}
}

// Stop will stop the relay loop.
func (pr *PacketRelay) Stop() {
	pr.closeOnce.Do(func() {
		close(pr.cancel)
	})

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

// EchoServer is a dummy server intended for testing. It will:
// - send sequential packets back to a client implementation, containing each the same payload
// and the same packet ID than incoming.
// - write every seen packet on the ACK array for the echo response.
type EchoServer struct {
	dataIn  chan *model.Packet
	dataOut chan *model.Packet

	// local counter for packet id
	outPacketID int

	// LocalSessionID is needed to produce incoming packets that pass sanity checks.
	LocalSessionID model.SessionID

	// RemoteSessionID is needed to produce ACKs.
	RemoteSessionID model.SessionID

	closeOnce sync.Once
	mu        sync.Mutex // Guards cancel
	cancel    chan struct{}
}

func NewEchoServer(dataIn, dataOut chan *model.Packet) *EchoServer {
	randomSessionID, err := bytesx.GenRandomBytes(8)
	if err != nil {
		panic(err)
	}
	return &EchoServer{
		dataIn:          dataIn,
		dataOut:         dataOut,
		outPacketID:     1,
		LocalSessionID:  model.SessionID(randomSessionID),
		RemoteSessionID: [8]byte{},
		closeOnce:       sync.Once{},
		mu:              sync.Mutex{},
		cancel:          make(chan struct{}),
	}
}

func (e *EchoServer) Start() {
	for {
		select {
		case <-e.cancel:
			return
		case p := <-e.dataIn:
			e.replyToPacketWithPayload(p.Payload, p.ID)
		}
	}
}

func (e *EchoServer) Stop() {
	e.closeOnce.Do(func() {
		close(e.cancel)
	})
}

func (e *EchoServer) replyToPacketWithPayload(payload []byte, toACK model.PacketID) {
	p := &model.Packet{
		Opcode:          model.P_CONTROL_V1,
		RemoteSessionID: e.RemoteSessionID,
		LocalSessionID:  e.LocalSessionID,
		ID:              toACK,
		Payload:         payload,
		ACKs:            []model.PacketID{toACK},
	}
	e.dataOut <- p
}

// TODO: write ReplayServer - server that receives a trace log and
// sends packets looking at the trace timings (and inferred losses).
// TODO: move to ReplayServer
/*
func (e *EchoServer) packetID() model.PacketID {
	e.mu.Lock()
	defer e.mu.Unlock()

	id := model.PacketID(e.outPacketID)
	e.outPacketID += 1
	return id
}
*/
