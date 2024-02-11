package model

import "testing"

func TestNegotiationState_String(t *testing.T) {
	tests := []struct {
		name string
		sns  NegotiationState
		want string
	}{
		{
			name: "undef",
			sns:  S_UNDEF,
			want: "S_UNDEF",
		},
		{
			name: "initial",
			sns:  S_INITIAL,
			want: "S_INITIAL",
		},
		{
			name: "pre start",
			sns:  S_PRE_START,
			want: "S_PRE_START",
		},
		{
			name: "start",
			sns:  S_START,
			want: "S_START",
		},
		{
			name: "sent key",
			sns:  S_SENT_KEY,
			want: "S_SENT_KEY",
		},
		{
			name: "got key",
			sns:  S_GOT_KEY,
			want: "S_GOT_KEY",
		},
		{
			name: "active",
			sns:  S_ACTIVE,
			want: "S_ACTIVE",
		},
		{
			name: "generated keys",
			sns:  S_GENERATED_KEYS,
			want: "S_GENERATED_KEYS",
		},
		{
			name: "error",
			sns:  S_ERROR,
			want: "S_ERROR",
		},
		{
			name: "unknown",
			sns:  NegotiationState(10),
			want: "S_INVALID",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.sns.String(); got != tt.want {
				t.Errorf("NegotiationState.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
