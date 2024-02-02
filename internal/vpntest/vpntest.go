// Package vpntest provides utilities for minivpn testing.
package vpntest

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ooni/minivpn/internal/model"
)

// TestPacket is used to simulate incoming packets over the network. The goal is to be able to
// have a compact representation of a sequence of packets, their type, and extra properties like
// inter-arrival time.
type TestPacket struct {
	// ID is the packet sequence
	ID int

	// Opcode is the OpenVPN packet opcode.
	Opcode model.Opcode

	// IAT is the inter-arrival time until the next packet is received.
	IAT time.Duration
}

// the test packet string is in the form:
// "[ID] OPCODE +42ms"
func NewTestPacketFromString(s string) (*TestPacket, error) {
	parts := strings.Split(s, " +")

	// Extracting id and opcode parts
	idAndOpcode := strings.Split(parts[0], " ")
	if len(idAndOpcode) != 2 {
		return nil, fmt.Errorf("invalid format for ID and opcode: %s", parts[0])
	}

	id, err := strconv.Atoi(strings.Trim(idAndOpcode[0], "[]"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse id: %v", err)
	}

	opcode, err := model.NewOpcodeFromString(idAndOpcode[1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse opcode: %v", err)
	}

	// Parsing duration part
	iatStr := parts[1]
	iat, err := time.ParseDuration(iatStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse duration: %v", err)
	}

	return &TestPacket{ID: id, Opcode: opcode, IAT: iat}, nil
}
