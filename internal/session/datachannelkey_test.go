package session

import "testing"

func Test_dataChannelKey_addRemoteKey(t *testing.T) {
	type fields struct {
		ready  bool
		remote *KeySource
	}
	type args struct {
		k *KeySource
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			"adding a keysource should make it ready",
			fields{false, &KeySource{}},
			args{&KeySource{}},
			false,
		},
		{
			"adding when ready should fail",
			fields{true, &KeySource{}},
			args{&KeySource{}},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dck := &DataChannelKey{
				ready:  tt.fields.ready,
				remote: tt.fields.remote,
			}
			if err := dck.AddRemoteKey(tt.args.k); (err != nil) != tt.wantErr {
				t.Errorf("dataChannelKey.AddRemoteKey() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !dck.Ready() {
				t.Errorf("should be ready")
			}
		})
	}
}
