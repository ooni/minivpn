package session

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ooni/minivpn/internal/bytesx"
)

// randomFn mocks the function to generate random bytes.
var randomFn = bytesx.GenRandomBytes

// errRandomBytes is the error returned when we cannot generate random bytes.
var errRandomBytes = errors.New("error generating random bytes")

// KeySource contains random data to generate keys.
type KeySource struct {
	R1        [32]byte
	R2        [32]byte
	PreMaster [48]byte
}

// Bytes returns the byte representation of a keySource.
func (k *KeySource) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.Write(k.PreMaster[:])
	buf.Write(k.R1[:])
	buf.Write(k.R2[:])
	return buf.Bytes()
}

// NewKeySource constructs a new [KeySource].
func NewKeySource() (*KeySource, error) {
	random1, err := randomFn(32)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errRandomBytes, err.Error())
	}

	var r1, r2 [32]byte
	var preMaster [48]byte
	copy(r1[:], random1)

	random2, err := randomFn(32)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errRandomBytes, err.Error())
	}
	copy(r2[:], random2)

	random3, err := randomFn(48)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errRandomBytes, err.Error())
	}
	copy(preMaster[:], random3)
	return &KeySource{
		R1:        r1,
		R2:        r2,
		PreMaster: preMaster,
	}, nil
}
