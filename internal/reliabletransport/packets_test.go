package reliabletransport

import (
	"testing"
	"time"
)

func Test_inFlightPacket_backoff(t *testing.T) {
	type fields struct {
		retries uint8
	}
	tests := []struct {
		name   string
		fields fields
		want   time.Duration
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &inFlightPacket{
				retries: tt.fields.retries,
			}
			if got := p.backoff(); got != tt.want {
				t.Errorf("inFlightPacket.backoff() = %v, want %v", got, tt.want)
			}
		})
	}
}
