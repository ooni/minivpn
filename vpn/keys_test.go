package vpn

// TODO move to data.go too

import (
	"reflect"
	"testing"
)

func Test_newKeySource(t *testing.T) {
	rnd := "0123456789"
	randomFn = func(int) ([]byte, error) {
		return []byte(rnd), nil
	}
	ks := &keySource{[]byte(rnd), []byte(rnd), []byte(rnd)}
	tests := []struct {
		name string
		want *keySource
	}{
		{"fakerandom", ks},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := newKeySource(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newKeySource() = %v, want %v", got, tt.want)
			}
		})
	}
}
