package vpn

//
// Key Sources
//

import (
	"errors"
	"fmt"
)

var (
	randomFn       = genRandomBytes
	errRandomBytes = errors.New("Error generating random bytes")
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
		return nil, fmt.Errorf("%w: %s", errRandomBytes, err.Error())
	}
	r2, err := randomFn(32)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errRandomBytes, err.Error())
	}
	preMaster, err := randomFn(48)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errRandomBytes, err.Error())
	}
	return &keySource{
		r1:        r1,
		r2:        r2,
		preMaster: preMaster,
	}, nil
}
