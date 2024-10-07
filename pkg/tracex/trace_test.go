// Package tracex implements a handshake tracer that can be passed to the TUN constructor to
// observe handshake events.
package tracex

import (
	"testing"

	"github.com/ooni/minivpn/internal/model"
)

func Test_maybeAddTagsFromPacket(t *testing.T) {
	tests := []struct {
		name          string
		packetPayload []byte
		expectedTags  []string
	}{
		{
			name:          "Empty payload",
			packetPayload: []byte{},
			expectedTags:  []string{},
		},
		{
			name:          "Payload too short",
			packetPayload: []byte{0x16, 0x00, 0x00, 0x00, 0x00},
			expectedTags:  []string{},
		},
		{
			name:          "Client Hello",
			packetPayload: []byte{0x16, 0x00, 0x00, 0x00, 0x00, 0x01},
			expectedTags:  []string{"client_hello"},
		},
		{
			name:          "Server Hello",
			packetPayload: []byte{0x16, 0x00, 0x00, 0x00, 0x00, 0x02},
			expectedTags:  []string{"server_hello"},
		},
		{
			name:          "No tag matching",
			packetPayload: []byte{0x17, 0x00, 0x00, 0x00, 0x00, 0x01},
			expectedTags:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &Event{Tags: []string{}}
			packet := &model.Packet{Payload: tt.packetPayload}

			maybeAddTagsFromPacket(event, packet)

			// Check if tags are as expected
			if len(event.Tags) != len(tt.expectedTags) {
				t.Fatalf("Expected %v tags, but got %v", len(tt.expectedTags), len(event.Tags))
			}

			for i, tag := range tt.expectedTags {
				if event.Tags[i] != tag {
					t.Errorf("Expected tag %v, but got %v", tag, event.Tags[i])
				}
			}
		})
	}
}
