package vpn

import (
	"fmt"
)

var (
	randomFn       = genRandomBytes
	errRandomBytes = "Error generating random bytes"
)

// random data to generate keys
type keySource struct {
	r1        []byte
	r2        []byte
	preMaster []byte
}

func (k *keySource) Bytes() []byte {
	r := append(k.preMaster, k.r1...)
	return append(r, k.r2...)
}

func newKeySource() (*keySource, error) {
	r1, err := randomFn(32)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errRandomBytes, err)
	}
	r2, err := randomFn(32)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errRandomBytes, err)
	}
	preMaster, err := randomFn(48)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errRandomBytes, err)
	}
	return &keySource{
		r1:        r1,
		r2:        r2,
		preMaster: preMaster,
	}, nil
}
