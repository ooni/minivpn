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

func Test_unpadTextPKCS7(t *testing.T) {
	type args struct {
		b  []byte
		bs int
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"empty", args{[]byte{}, 2}, nil, true},
		{"two-two", args{[]byte{1, 1, 2, 2}, 2}, []byte{1, 1}, false},
		{"one-two", args{[]byte{9, 1}, 2}, []byte{9}, false},
		{"two-four", args{[]byte{1, 3, 2, 2}, 4}, []byte{1, 3}, false},
		{"three-four", args{[]byte{1, 3, 5, 1}, 4}, []byte{1, 3, 5}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := unpadTextPKCS7(tt.args.b, tt.args.bs)
			if (err != nil) != tt.wantErr {
				t.Errorf("unpadTextPKCS7() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("unpadTextPKCS7() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_padTextPKCS7(t *testing.T) {
	type args struct {
		b  []byte
		bs int
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"one-two", args{[]byte{0}, 2}, []byte{0, 1}, false},
		{"two-two", args{[]byte{0, 0}, 2}, []byte{0, 0, 2, 2}, false},
		{"one-four", args{[]byte{0}, 4}, []byte{0, 3, 3, 3}, false},
		{"two-four", args{[]byte{0, 0}, 4}, []byte{0, 0, 2, 2}, false},
		{"three-four", args{[]byte{9, 9, 9}, 4}, []byte{9, 9, 9, 1}, false},
		{"four-four", args{[]byte{9, 8, 7, 6}, 4}, []byte{9, 8, 7, 6, 4, 4, 4, 4}, false},
		{"toobig-bs", args{[]byte{0}, 256}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := padTextPKCS7(tt.args.b, tt.args.bs)
			if (err != nil) != tt.wantErr {
				t.Errorf("padTextPKCS7() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("padTextPKCS7() = %v, want %v", got, tt.want)
			}
		})
	}
}
