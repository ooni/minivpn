// Package vpntest provides utilities for minivpn testing.
package vpntest

import (
	"errors"
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
	// Opcode is the OpenVPN packet opcode.
	Opcode model.Opcode

	// ID is the packet sequence
	ID int

	// ACKs is the ack array in this packet
	ACKs []int

	// IAT is the inter-arrival time until the next packet is received.
	IAT time.Duration
}

// the test packet string is in the form:
// "[ID] OPCODE +42ms"
func NewTestPacketFromString(s string) (*TestPacket, error) {
	parts := strings.Split(s, " +")

	// Extracting id, opcode and ack parts
	head := strings.Split(parts[0], " ")
	if len(head) < 2 || len(head) > 3 {
		return nil, fmt.Errorf("invalid format for ID-op-acks: %s", parts[0])
	}

	id, err := strconv.Atoi(strings.Trim(head[0], "[]"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse id: %v", err)
	}

	opcode, err := model.NewOpcodeFromString(head[1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse opcode: %v", err)
	}

	acks := []int{}

	if len(head) == 3 {
		acks, err = parseACKs(strings.Trim(head[2], "()"))
		fmt.Println("acks:", acks)
		if err != nil {
			return nil, fmt.Errorf("failed to parse opcode: %v", err)
		}
	}

	// Parsing duration part
	iatStr := parts[1]
	iat, err := time.ParseDuration(iatStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse duration: %v", err)
	}

	return &TestPacket{ID: id, Opcode: opcode, ACKs: acks, IAT: iat}, nil
}

var errBadACK = errors.New("wrong ack string")

func parseACKs(s string) ([]int, error) {
	acks := []int{}
	h := strings.Split(s, "ack:")
	if len(h) != 2 {
		return acks, errBadACK
	}
	values := strings.Split(h[1], ",")
	for _, v := range values {
		n, err := strconv.Atoi(v)
		if err == nil {
			acks = append(acks, n)
		}
	}
	return acks, nil
}
