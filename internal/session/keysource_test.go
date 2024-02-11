package session

import (
	"bytes"
	"reflect"
	"testing"
)

const (
	rnd16 = "0123456789012345"
	rnd32 = "01234567890123456789012345678901"
	rnd48 = "012345678901234567890123456789012345678901234567"
)

func makeTestKeys() ([32]byte, [32]byte, [48]byte) {
	r1 := *(*[32]byte)([]byte(rnd32))
	r2 := *(*[32]byte)([]byte(rnd32))
	r3 := *(*[48]byte)([]byte(rnd48))
	return r1, r2, r3
}

// getDeterministicRandomKeySize returns a sequence of integers
// using the map in the closure. we use this to construct a deterministic
// random function to replace the random function used in the real client.
func getDeterministicRandomKeySizeFn() func() int {
	var rndSeq = map[int]int{
		1: 32,
		2: 32,
		3: 48,
	}
	i := 1
	f := func() int {
		v := rndSeq[i]
		i += 1
		return v
	}
	return f
}

func TestNewKeySource(t *testing.T) {

	genKeySizeFn := getDeterministicRandomKeySizeFn()

	// we replace the global random function used in the constructor
	randomFn = func(int) ([]byte, error) {
		switch genKeySizeFn() {
		case 48:
			return []byte(rnd48), nil
		default:
			return []byte(rnd32), nil
		}
	}

	r1, r2, premaster := makeTestKeys()
	ks := &KeySource{r1, r2, premaster}

	tests := []struct {
		name string
		want *KeySource
	}{
		{
			name: "test generation of a new key with mocked random data",
			want: ks,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := NewKeySource(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newKeySource() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_keySource_Bytes(t *testing.T) {
	r1, r2, premaster := makeTestKeys()
	goodSerialized := append(premaster[:], r1[:]...)
	goodSerialized = append(goodSerialized, r2[:]...)

	type fields struct {
		r1        [32]byte
		r2        [32]byte
		preMaster [48]byte
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		{
			name: "good keysource",
			fields: fields{
				r1:        r1,
				r2:        r2,
				preMaster: premaster,
			},
			want: goodSerialized,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &KeySource{
				R1:        tt.fields.r1,
				R2:        tt.fields.r2,
				PreMaster: tt.fields.preMaster,
			}
			if got := k.Bytes(); !bytes.Equal(got, tt.want) {
				t.Errorf("keySource.Bytes() = %v, want %v", got, tt.want)
			}
		})
	}
}
