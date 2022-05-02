package vpn

import (
	"reflect"
	"testing"
)

func Test_genRandomBytes(t *testing.T) {
	const smallBuffer = 128
	data, err := genRandomBytes(smallBuffer)
	if err != nil {
		t.Fatal("unexpected error", err)
	}
	if len(data) != smallBuffer {
		t.Fatal("unexpected returned buffer length")
	}
}

func Test_encodeOptionString(t *testing.T) {

	veryLargeStr := string(make([]byte, 1<<16))

	type args struct {
		s string
	}

	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"goodEncode", args{"test"}, []byte{0, 5, 116, 101, 115, 116, 0}, false},
		{"empty", args{""}, []byte{0, 1, 0}, false},
		{"large", args{veryLargeStr}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encodeOptionString(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("encodeOptionString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("encodeOptionString() = %v, want %v", got, tt.want)
			}
		})
	}
}
