package emitter

import (
	"encoding/json"
	"io"

	"github.com/m-lab/ndt7-client-go/spec"
)

// jsonEmitter is a jsonEmitter emitter. It emits messages consistent with
// the cmd/ndt7-client/main.go documentation for `-format=json`.
type jsonEmitter struct {
	io.Writer
}

// NewJSON creates a new JSON emitter
func NewJSON(w io.Writer) Emitter {
	return jsonEmitter{
		Writer: w,
	}
}

func (j jsonEmitter) emitData(data []byte) error {
	_, err := j.Write(append(data, byte('\n')))
	return err
}

func (j jsonEmitter) emitInterface(any interface{}) error {
	data, err := json.Marshal(any)
	if err != nil {
		return err
	}
	return j.emitData(data)
}

type batchEvent struct {
	Key   string
	Value interface{}
}

type batchValue struct {
	spec.Measurement
	Failure string `json:",omitempty"`
	Server  string `json:",omitempty"`
}

// OnStarting emits the starting event
func (j jsonEmitter) OnStarting(test spec.TestKind) error {
	return j.emitInterface(batchEvent{
		Key: "starting",
		Value: batchValue{
			Measurement: spec.Measurement{
				Test: test,
			},
		},
	})
}

// OnError emits the error event
func (j jsonEmitter) OnError(test spec.TestKind, err error) error {
	return j.emitInterface(batchEvent{
		Key: "error",
		Value: batchValue{
			Measurement: spec.Measurement{
				Test: test,
			},
			Failure: err.Error(),
		},
	})
}

// OnConnected emits the connected event
func (j jsonEmitter) OnConnected(test spec.TestKind, fqdn string) error {
	return j.emitInterface(batchEvent{
		Key: "connected",
		Value: batchValue{
			Measurement: spec.Measurement{
				Test: test,
			},
			Server: fqdn,
		},
	})
}

// OnDownloadEvent handles an event emitted during the download
func (j jsonEmitter) OnDownloadEvent(m *spec.Measurement) error {
	return j.emitInterface(batchEvent{
		Key:   "measurement",
		Value: m,
	})
}

// OnUploadEvent handles an event emitted during the upload
func (j jsonEmitter) OnUploadEvent(m *spec.Measurement) error {
	return j.emitInterface(batchEvent{
		Key:   "measurement",
		Value: m,
	})
}

// OnComplete is the event signalling the end of the test
func (j jsonEmitter) OnComplete(test spec.TestKind) error {
	return j.emitInterface(batchEvent{
		Key: "complete",
		Value: batchValue{
			Measurement: spec.Measurement{
				Test: test,
			},
		},
	})
}

// OnSummary handles the summary event, emitted after the test is over.
func (j jsonEmitter) OnSummary(s *Summary) error {
	return j.emitInterface(s)
}
