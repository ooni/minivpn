// Package bytesx provides functions operating on bytes.
//
// Specifically we implement these operations:
//
// 1. generating random bytes;
//
// 2. OpenVPN options encoding and decoding;
//
// 3. PKCS#7 padding and unpadding.
package bytesx

import (
	"bytes"
	"errors"
	"io"
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_GenRandomBytes(t *testing.T) {
	const smallBuffer = 128
	data, err := GenRandomBytes(smallBuffer)
	if err != nil {
		t.Fatal("unexpected error", err)
	}
	if len(data) != smallBuffer {
		t.Fatal("unexpected returned buffer length")
	}
}

func Test_EncodeOptionStringToBytes(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr error
	}{{
		name: "common case",
		args: args{
			s: "test",
		},
		want:    []byte{0, 5, 116, 101, 115, 116, 0},
		wantErr: nil,
	}, {
		name: "encoding empty string",
		args: args{
			s: "",
		},
		want:    []byte{0, 1, 0},
		wantErr: nil,
	}, {
		name: "encoding a very large string",
		args: args{
			s: string(make([]byte, 1<<16)),
		},
		want:    nil,
		wantErr: ErrEncodeOption,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeOptionStringToBytes(tt.args.s)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("encodeOptionStringToBytes() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func Test_DecodeOptionStringFromBytes(t *testing.T) {
	type args struct {
		b []byte
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr error
	}{{
		name: "with zero-length input",
		args: args{
			b: nil,
		},
		want:    "",
		wantErr: ErrDecodeOption,
	}, {
		name: "with input length equal to one",
		args: args{
			b: []byte{0x00},
		},
		want:    "",
		wantErr: ErrDecodeOption,
	}, {
		name: "with input length equal to two",
		args: args{
			b: []byte{0x00, 0x00},
		},
		want:    "",
		wantErr: ErrDecodeOption,
	}, {
		name: "with length mismatch and length < actual length",
		args: args{
			b: []byte{
				0x00, 0x03, // length = 3
				0x61, 0x61, 0x61, 0x61, 0x61, // aaaaa
				0x00, // trailing zero
			},
		},
		want:    "",
		wantErr: ErrDecodeOption,
	}, {
		name: "with length mismatch and length > actual length",
		args: args{
			b: []byte{
				0x00, 0x44, // length = 68
				0x61, 0x61, 0x61, 0x61, 0x61, // aaaaa
				0x00, // trailing zero
			},
		},
		want:    "",
		wantErr: ErrDecodeOption,
	}, {
		name: "with missing trailing \\0",
		args: args{
			b: []byte{
				0x00, 0x05, // length = 5
				0x61, 0x61, 0x61, 0x61, 0x61, // aaaaa
			},
		},
		want:    "",
		wantErr: ErrDecodeOption,
	}, {
		name: "with valid input",
		args: args{
			b: []byte{
				0x00, 0x06, // length = 6
				0x61, 0x61, 0x61, 0x61, 0x61, // aaaaa
				0x00, // trailing zero
			},
		},
		want:    "aaaaa",
		wantErr: nil,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeOptionStringFromBytes(tt.args.b)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("decodeOptionStringFromBytes() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func Test_BytesUnpadPKCS7(t *testing.T) {
	type args struct {
		b         []byte
		blockSize int
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr error
	}{{
		name: "with too-large blockSize",
		args: args{
			b:         []byte{0x00, 0x00, 0x00},
			blockSize: math.MaxUint8 + 1, // too large
		},
		want:    nil,
		wantErr: ErrUnpaddingPKCS7,
	}, {
		name: "with zero-length array",
		args: args{
			b:         nil,
			blockSize: 2,
		},
		want:    nil,
		wantErr: ErrUnpaddingPKCS7,
	}, {
		name: "with 0x00 used as padding",
		args: args{
			b: []byte{
				0x61, 0x61, // block ("aa")
				0x00, 0x00, // padding
			},
			blockSize: 2,
		},
		want:    nil,
		wantErr: ErrUnpaddingPKCS7,
	}, {
		name: "with padding larger than block size",
		args: args{
			b: []byte{
				0x61, 0x61, // block ("aa")
				0x03, 0x03, // padding
			},
			blockSize: 2,
		},
		want:    nil,
		wantErr: ErrUnpaddingPKCS7,
	}, {
		name: "with blocksize == 4 and len(data) == 0",
		args: args{
			b: []byte{
				0x04, 0x04, 0x04, 0x04, // padding
			},
			blockSize: 4,
		},
		want:    []byte{},
		wantErr: nil,
	}, {
		name: "with blocksize == 4 and len(data) == 1",
		args: args{
			b: []byte{
				0xde,             // data
				0x03, 0x03, 0x03, // padding
			},
			blockSize: 4,
		},
		want:    []byte{0xde},
		wantErr: nil,
	}, {
		name: "with blocksize == 4 and len(data) == 2",
		args: args{
			b: []byte{
				0xde, 0xad, // data
				0x02, 0x02, // padding
			},
			blockSize: 4,
		},
		want:    []byte{0xde, 0xad},
		wantErr: nil,
	}, {
		name: "with blocksize == 4 and len(data) == 3",
		args: args{
			b: []byte{
				0xde, 0xad, 0xbe, // data
				0x01, // padding
			},
			blockSize: 4,
		},
		want:    []byte{0xde, 0xad, 0xbe},
		wantErr: nil,
	}, {
		name: "with blocksize == 4 and len(data) == 4",
		args: args{
			b: []byte{
				0xde, 0xad, 0xbe, 0xff, // data
				0x04, 0x04, 0x04, 0x04, // padding
			},
			blockSize: 4,
		},
		want:    []byte{0xde, 0xad, 0xbe, 0xff},
		wantErr: nil,
	}, {
		name: "with blocksize == 4 and len(data) == 5",
		args: args{
			b: []byte{
				0xde, 0xad, 0xbe, 0xff, 0xab, // data
				0x03, 0x03, 0x03, // padding
			},
			blockSize: 4,
		},
		want:    []byte{0xde, 0xad, 0xbe, 0xff, 0xab},
		wantErr: nil,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BytesUnpadPKCS7(tt.args.b, tt.args.blockSize)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("bytesUnpadPKCS7() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func Test_BytesPadPKCS7(t *testing.T) {
	type args struct {
		b         []byte
		blockSize int
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr error
	}{{
		name: "with too-large block size",
		args: args{
			b:         []byte{0x00, 0x00, 0x00},
			blockSize: math.MaxUint8 + 1,
		},
		want:    nil,
		wantErr: ErrPaddingPKCS7,
	},
		{
			name: "with blockSize == 4 and len(data) == 0",
			args: args{
				b:         nil,
				blockSize: 4,
			},
			want: []byte{
				0x04, 0x04, 0x04, 0x04, // only padding
			},
			wantErr: nil,
		}, {
			name: "with blockSize == 4 and len(data) == 1",
			args: args{
				b: []byte{
					0xde, // len(data) == 1
				},
				blockSize: 4,
			},
			want: []byte{
				0xde,             // data
				0x03, 0x03, 0x03, // padding
			},
			wantErr: nil,
		}, {
			name: "with blockSize == 4 and len(data) == 2",
			args: args{
				b: []byte{
					0xde, 0xad, // len(data) == 2
				},
				blockSize: 4,
			},
			want: []byte{
				0xde, 0xad, // data
				0x02, 0x02, // padding
			},
			wantErr: nil,
		}, {
			name: "with blockSize == 4 and len(data) == 3",
			args: args{
				b: []byte{
					0xde, 0xad, 0xbe, // len(data) == 3
				},
				blockSize: 4,
			},
			want: []byte{
				0xde, 0xad, 0xbe, //data
				0x01, // padding
			},
			wantErr: nil,
		}, {
			name: "with blockSize == 4 and len(data) == 4",
			args: args{
				b: []byte{
					0xde, 0xad, 0xbe, 0xef, // len(data) == 4
				},
				blockSize: 4,
			},
			want: []byte{
				0xde, 0xad, 0xbe, 0xef, // data
				0x04, 0x04, 0x04, 0x04, // padding
			},
			wantErr: nil,
		}, {
			name: "with blocksize == 4 and len(data) == 5",
			args: args{
				b: []byte{
					0xde, 0xad, 0xbe, 0xef, 0xab, // len(data) == 5
				},
				blockSize: 4,
			},
			want: []byte{
				0xde, 0xad, 0xbe, 0xef, 0xab, // data
				0x03, 0x03, 0x03, // padding
			},
			wantErr: nil,
		}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BytesPadPKCS7(tt.args.b, tt.args.blockSize)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("bytesPadPKCS7() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

// Regression test for MIV-01-002
func Test_Crash_bytesPadPCKS7(t *testing.T) {
	// we want to panic and crash because a zero or negative block size should not
	// be controllable by the user. if this happens, we have a seriously misconfigured
	// data channel cipher.
	assertPanic(t, func() { BytesPadPKCS7(nil, 0) })
	assertPanic(t, func() { BytesPadPKCS7([]byte{0xaa, 0xab}, -1) })
}

func assertPanic(t *testing.T, f func()) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected code to panic")
		}
	}()
	f()
}

func TestReadUint32(t *testing.T) {
	type args struct {
		buf *bytes.Buffer
	}
	tests := []struct {
		name    string
		args    args
		want    uint32
		wantErr error
	}{
		{
			name:    "empty buffer raises EOF",
			args:    args{&bytes.Buffer{}},
			want:    0,
			wantErr: io.EOF,
		},
		{
			name:    "buffer reads 1",
			args:    args{bytes.NewBuffer([]byte{0x00, 0x00, 0x00, 0x01})},
			want:    1,
			wantErr: nil,
		},
		{
			name:    "0xffffffff",
			args:    args{bytes.NewBuffer([]byte{0xff, 0xff, 0xff, 0xff})},
			want:    4294967295,
			wantErr: nil,
		},
		{
			name:    "read only 4 if the buffer is bigger",
			args:    args{bytes.NewBuffer([]byte{0x00, 0x000, 0x00, 0x01, 0xff})},
			want:    1,
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadUint32(tt.args.buf)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ReadUint32() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ReadUint32() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWriteUint32(t *testing.T) {
	type args struct {
		buf *bytes.Buffer
		val uint32
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "empty value gets 4 zeroes appended",
			args: args{
				buf: bytes.NewBuffer([]byte{}),
				val: 0,
			},
			want: []byte{0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "append 1 to an existing buffer",
			args: args{
				buf: bytes.NewBuffer([]byte{0xff}),
				val: 1,
			},
			want: []byte{0xff, 0x00, 0x00, 0x00, 0x01},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			WriteUint32(tt.args.buf, tt.args.val)
			got := tt.args.buf.Bytes()
			if !bytes.Equal(got, tt.want) {
				t.Errorf("WriteUint32(); got = %v, want = %v", got, tt.want)

			}
		})
	}
}

func TestWriteUint24(t *testing.T) {
	type args struct {
		buf *bytes.Buffer
		val uint32
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "empty value gets 3 zeroes appended",
			args: args{
				buf: bytes.NewBuffer([]byte{}),
				val: 0,
			},
			want: []byte{0x00, 0x00, 0x00},
		},
		{
			name: "append 1 to an existing buffer",
			args: args{
				buf: bytes.NewBuffer([]byte{0xff}),
				val: 1,
			},
			want: []byte{0xff, 0x00, 0x00, 0x01},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			WriteUint24(tt.args.buf, tt.args.val)
			got := tt.args.buf.Bytes()
			if !bytes.Equal(got, tt.want) {
				t.Errorf("WriteUint24(); got = %v, want = %v", got, tt.want)
			}
		})
	}
}
