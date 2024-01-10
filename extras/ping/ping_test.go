package ping

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ooni/minivpn/vpn/mocks"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func TestProcessPacket_IDMismatch(t *testing.T) {
	pinger := makeTestPinger()
	pinger.protocol = "icmp"
	shouldBe0 := 0
	// this function should not be called because the tracker is mismatched
	pinger.OnRecv = func(pkt *Packet) {
		shouldBe0++
	}

	currentUUID, err := pinger.getCurrentTrackerUUID().MarshalBinary()
	if err != nil {
		t.Fatal(fmt.Sprintf("unable to marshal UUID binary: %s", err))
	}
	data := append(timeToBytes(time.Now()), currentUUID...)
	if remainSize := pinger.Size - timeSliceLength - trackerLength; remainSize > 0 {
		data = append(data, bytes.Repeat([]byte{1}, remainSize)...)
	}

	body := &icmp.Echo{
		ID:   999999,
		Seq:  pinger.sequence,
		Data: data,
	}

	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: body,
	}

	msgBytes, _ := msg.Marshal(nil)

	pkt := packet{
		nbytes: len(msgBytes),
		bytes:  msgBytes,
		ttl:    24,
	}

	err = pinger.processPacket(&pkt)
	AssertNoError(t, err)
	AssertTrue(t, shouldBe0 == 0)
}

func TestProcessPacket_TrackerMismatch(t *testing.T) {
	pinger := makeTestPinger()
	shouldBe0 := 0
	// this function should not be called because the tracker is mismatched
	pinger.OnRecv = func(pkt *Packet) {
		shouldBe0++
	}

	testUUID, err := uuid.New().MarshalBinary()
	if err != nil {
		t.Fatal(fmt.Sprintf("unable to marshal UUID binary: %s", err))
	}
	data := append(timeToBytes(time.Now()), testUUID...)
	if remainSize := pinger.Size - timeSliceLength - trackerLength; remainSize > 0 {
		data = append(data, bytes.Repeat([]byte{1}, remainSize)...)
	}

	body := &icmp.Echo{
		ID:   pinger.id,
		Seq:  pinger.sequence,
		Data: data,
	}

	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: body,
	}

	msgBytes, _ := msg.Marshal(nil)

	pkt := packet{
		nbytes: len(msgBytes),
		bytes:  msgBytes,
		ttl:    24,
	}

	err = pinger.processPacket(&pkt)
	AssertNoError(t, err)
	AssertTrue(t, shouldBe0 == 0)
}

func TestProcessPacket_LargePacket(t *testing.T) {
	pinger := makeTestPinger()
	pinger.Size = 4096

	currentUUID, err := pinger.getCurrentTrackerUUID().MarshalBinary()
	if err != nil {
		t.Fatal(fmt.Sprintf("unable to marshal UUID binary: %s", err))
	}
	data := append(timeToBytes(time.Now()), currentUUID...)
	if remainSize := pinger.Size - timeSliceLength - trackerLength; remainSize > 0 {
		data = append(data, bytes.Repeat([]byte{1}, remainSize)...)
	}

	body := &icmp.Echo{
		ID:   pinger.id,
		Seq:  pinger.sequence,
		Data: data,
	}

	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: body,
	}

	msgBytes, _ := msg.Marshal(nil)

	pkt := packet{
		nbytes: len(msgBytes),
		bytes:  msgBytes,
		ttl:    24,
	}

	err = pinger.processPacket(&pkt)
	AssertNoError(t, err)
}

// TODO this one is failing
// func TestProcessPacket_PacketTooSmall(t *testing.T)

// do not return err
/*
 func TestNewPingerInvalid(t *testing.T) {
 	_ := New("127.0.0.0.1", &mocks.Conn{})
 	AssertError(t, "127.0.0.0.1")

 	_  = New("127..0.0.1", &mocks.Conn{})
 	AssertError(t, "127..0.0.1")

 	_ = New(":::1", &mocks.Conn{})
 	AssertError(t, ":::1")

 }
*/

func TestStatisticsSunny(t *testing.T) {
	// Create a localhost ipv4 pinger
	p := New("127.0.0.1", &mocks.Conn{})

	p.PacketsSent = 10
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})

	stats := p.Statistics()
	if stats.PacketsRecv != 10 {
		t.Errorf("Expected %v, got %v", 10, stats.PacketsRecv)
	}
	if stats.PacketsSent != 10 {
		t.Errorf("Expected %v, got %v", 10, stats.PacketsSent)
	}
	if stats.PacketLoss != 0 {
		t.Errorf("Expected %v, got %v", 0, stats.PacketLoss)
	}
	if stats.MinRtt != time.Duration(1000) {
		t.Errorf("Expected %v, got %v", time.Duration(1000), stats.MinRtt)
	}
	if stats.MaxRtt != time.Duration(1000) {
		t.Errorf("Expected %v, got %v", time.Duration(1000), stats.MaxRtt)
	}
	if stats.AvgRtt != time.Duration(1000) {
		t.Errorf("Expected %v, got %v", time.Duration(1000), stats.AvgRtt)
	}
	if stats.StdDevRtt != time.Duration(0) {
		t.Errorf("Expected %v, got %v", time.Duration(0), stats.StdDevRtt)
	}
}

func TestStatisticsLossy(t *testing.T) {
	// Create a localhost ipv4 pinger
	p := New("127.0.0.1", &mocks.Conn{})

	p.PacketsSent = 20
	p.updateStatistics(&Packet{Rtt: time.Duration(10)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(10000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(800)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(40)})
	p.updateStatistics(&Packet{Rtt: time.Duration(100000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})

	stats := p.Statistics()
	if stats.PacketsRecv != 10 {
		t.Errorf("Expected %v, got %v", 10, stats.PacketsRecv)
	}
	if stats.PacketsSent != 20 {
		t.Errorf("Expected %v, got %v", 20, stats.PacketsSent)
	}
	if stats.PacketLoss != 50 {
		t.Errorf("Expected %v, got %v", 50, stats.PacketLoss)
	}
	if stats.MinRtt != time.Duration(10) {
		t.Errorf("Expected %v, got %v", time.Duration(10), stats.MinRtt)
	}
	if stats.MaxRtt != time.Duration(100000) {
		t.Errorf("Expected %v, got %v", time.Duration(100000), stats.MaxRtt)
	}
	if stats.AvgRtt != time.Duration(11585) {
		t.Errorf("Expected %v, got %v", time.Duration(11585), stats.AvgRtt)
	}
	if stats.StdDevRtt != time.Duration(29603) {
		t.Errorf("Expected %v, got %v", time.Duration(29603), stats.StdDevRtt)
	}
}

// Test helpers
func makeTestPinger() *Pinger {
	conn := makeConn()
	pinger := New("127.0.0.1", conn)

	pinger.ipv4 = true
	pinger.Target = "127.0.0.2"
	pinger.protocol = "icmp"
	pinger.id = 123
	pinger.Size = 0

	return pinger
}

func AssertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("Expected No Error but got %s, Stack:\n%s",
			err, string(debug.Stack()))
	}
}

func AssertError(t *testing.T, err error, info string) {
	t.Helper()
	if err == nil {
		t.Errorf("Expected Error but got %s, %s, Stack:\n%s",
			err, info, string(debug.Stack()))
	}
}

func AssertEqualStrings(t *testing.T, expected, actual string) {
	t.Helper()
	if expected != actual {
		t.Errorf("Expected %s, got %s, Stack:\n%s",
			expected, actual, string(debug.Stack()))
	}
}

func AssertNotEqualStrings(t *testing.T, expected, actual string) {
	t.Helper()
	if expected == actual {
		t.Errorf("Expected %s, got %s, Stack:\n%s",
			expected, actual, string(debug.Stack()))
	}
}

func AssertTrue(t *testing.T, b bool) {
	t.Helper()
	if !b {
		t.Errorf("Expected True, got False, Stack:\n%s", string(debug.Stack()))
	}
}

func AssertFalse(t *testing.T, b bool) {
	t.Helper()
	if b {
		t.Errorf("Expected False, got True, Stack:\n%s", string(debug.Stack()))
	}
}

func BenchmarkProcessPacket(b *testing.B) {
	pinger := New("127.0.0.1", &mocks.Conn{})

	pinger.ipv4 = true
	pinger.Target = "127.0.0.1"
	pinger.protocol = "ip4:icmp"
	pinger.id = 123

	currentUUID, err := pinger.getCurrentTrackerUUID().MarshalBinary()
	if err != nil {
		b.Fatal(fmt.Sprintf("unable to marshal UUID binary: %s", err))
	}
	data := append(timeToBytes(time.Now()), currentUUID...)
	if remainSize := pinger.Size - timeSliceLength - trackerLength; remainSize > 0 {
		data = append(data, bytes.Repeat([]byte{1}, remainSize)...)
	}

	body := &icmp.Echo{
		ID:   pinger.id,
		Seq:  pinger.sequence,
		Data: data,
	}

	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: body,
	}

	msgBytes, _ := msg.Marshal(nil)

	pkt := packet{
		nbytes: len(msgBytes),
		bytes:  msgBytes,
		ttl:    24,
	}

	for k := 0; k < b.N; k++ {
		pinger.processPacket(&pkt)
	}
}

func TestProcessPacket_IgnoresDuplicateSequence(t *testing.T) {
	pinger := makeTestPinger()
	shouldBe0 := 0
	dups := 0

	pinger.OnRecv = func(pkt *Packet) {
		shouldBe0++
	}

	pinger.OnDuplicateRecv = func(pkt *Packet) {
		dups++
	}

	src := net.ParseIP("127.0.0.2")
	dst := net.ParseIP("127.0.0.1")
	currentUUID := pinger.getCurrentTrackerUUID()

	data := newIcmpData(&src, &dst, 8, 64, 0, 123, currentUUID)

	// register the sequence as sent
	pinger.awaitingSequences[currentUUID][0] = struct{}{}

	msgBytes := data
	pkt := packet{
		nbytes: len(msgBytes),
		bytes:  msgBytes,
		ttl:    24,
	}

	err := pinger.processPacket(&pkt)
	AssertNoError(t, err)
	// receive a duplicate
	err = pinger.processPacket(&pkt)
	AssertNoError(t, err)

	AssertTrue(t, shouldBe0 == 1)
	AssertTrue(t, dups == 1)
	AssertTrue(t, pinger.PacketsRecvDuplicates == 1)
}

func TestRunBadWrite(t *testing.T) {
	conn := makeConnBadWrite()

	pinger := New("127.0.0.1", conn)
	pinger.Count = 1
	pinger.Target = "127.0.0.2"
	pinger.Interval = 1 * time.Millisecond
	pinger.Timeout = time.Second

	err := pinger.Run(context.Background())
	AssertTrue(t, err != nil)

	stats := pinger.Statistics()
	AssertTrue(t, stats != nil)
	if stats == nil {
		t.FailNow()
	}
	AssertTrue(t, stats.PacketsSent == 0)
	AssertTrue(t, stats.PacketsRecv == 0)
}

func makeConnBadWrite() net.Conn {
	conn := makeConn()
	conn.MockWrite = func([]byte) (int, error) {
		return 0, errors.New("bad write")
	}
	conn.MockRead = func([]byte) (int, error) {
		return 0, nil
	}
	return conn
}

func makeConnBadRead() net.Conn {
	conn := makeConn()
	conn.MockRead = func([]byte) (int, error) {
		// hacky, but I need to give time to the send loop to update the SentPackets counter too
		time.Sleep(10 * time.Millisecond)
		return 0, errors.New("bad read")
	}
	conn.MockWrite = func(b []byte) (int, error) {
		return len(b), nil
	}
	return conn
}

func TestRunBadRead(t *testing.T) {
	conn := makeConnBadRead()
	pinger := New("127.0.0.1", conn)
	pinger.Count = 1
	pinger.Target = "127.0.0.2"
	pinger.Interval = time.Millisecond
	pinger.Timeout = time.Second

	err := pinger.Run(context.Background())
	AssertTrue(t, err != nil)

	stats := pinger.Statistics()
	AssertTrue(t, stats != nil)
	if stats == nil {
		t.FailNow()
	}
	AssertTrue(t, stats.PacketsSent == 1)
	AssertTrue(t, stats.PacketsRecv == 0)
	AssertTrue(t, pinger.PacketLoss() == 100)
}

func TestPrintStats(t *testing.T) {
	conn := makeConnBadRead()
	pinger := New("127.0.0.1", conn)
	pinger.Count = 1
	pinger.Target = "127.0.0.2"
	pinger.Interval = time.Millisecond
	pinger.Timeout = time.Second
	_ = pinger.Run(context.Background())
	pinger.PrintStats()
}

func makeConn() *mocks.Conn {
	mockAddr := &mocks.Addr{}
	mockAddr.MockString = func() string {
		return "127.0.0.1"
	}
	mockAddr.MockNetwork = func() string {
		return "udp"
	}
	conn := &mocks.Conn{}
	conn.MockLocalAddr = func() net.Addr {
		return mockAddr
	}
	conn.MockClose = func() error {
		return nil
	}
	conn.MockSetReadDeadline = func(time.Time) error {
		return nil
	}
	return conn
}

type witness struct {
	closed bool
}

func makeConnWitnessClose(w *witness) *mocks.Conn {
	c := &mocks.Conn{}
	c.MockClose = func() error {
		w.closed = true
		return nil
	}
	return c
}

func Test_NewFromSharedConnectionDoesNotCloseConn(t *testing.T) {
	t.Run("shared connection does not close", func(t *testing.T) {
		w := &witness{}
		conn := makeConnWitnessClose(w)

		p := NewFromSharedConnection("1.1.1.1", conn)
		p.Run(context.Background())
		if w.closed {
			t.Error("should not have closed conn")
		}
	})
	t.Run("default does close", func(t *testing.T) {
		w := &witness{}
		conn := makeConnWitnessClose(w)

		p := New("1.1.1.1", conn)
		p.Run(context.Background())
		if !w.closed {
			t.Error("should have closed conn")
		}
	})
}
