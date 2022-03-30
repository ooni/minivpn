package vpn

import (
	"testing"
)

func Test_isControlOpcode(t *testing.T) {
	type args struct {
		b byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"hardResetServer", args{byte(pControlHardResetServerV2)}, true},
		{"control1", args{byte(pControlV1)}, true},
		{"zero", args{0}, false},
		{"ones", args{255}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isControlOpcode(tt.args.b); got != tt.want {
				t.Errorf("isControlOpcode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isDataOpcode(t *testing.T) {
	type args struct {
		b byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"data", args{byte(pDataV1)}, true},
		{"zero", args{byte(0)}, false},
		{"ones", args{byte(255)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDataOpcode(tt.args.b); got != tt.want {
				t.Errorf("isDataOpcode() = %v, want %v", got, tt.want)
			}
		})
	}
}
