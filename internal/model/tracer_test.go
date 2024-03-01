package model

import "time"

type testTracer struct{}

func (tt *testTracer) TimeNow() time.Time {
	return time.Now()
}

func (tt *testTracer) OnStateChange(state NegotiationState)                                        {}
func (tt *testTracer) OnIncomingPacket(packet *Packet, stage NegotiationState)                     {}
func (tt *testTracer) OnOutgoingPacket(packet *Packet, stage NegotiationState, retries int)        {}
func (tt *testTracer) OnDroppedPacket(direction Direction, stage NegotiationState, packet *Packet) {}

func newTestTracer() *testTracer {
	return &testTracer{}
}
