package vpn

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

func newKeySource() *keySource {
	r1, err := genRandomBytes(32)
	if err != nil {
		panic("Error generating random bytes")
	}
	r2, err := genRandomBytes(32)
	if err != nil {
		panic("Error generating random bytes")
	}
	preMaster, err := genRandomBytes(48)
	if err != nil {
		panic("Error generating random bytes")
	}
	return &keySource{
		r1:        r1,
		r2:        r2,
		preMaster: preMaster,
	}
}
