// Package emitter contains the ndt7-client emitter.
package emitter

import (
	"github.com/m-lab/ndt7-client-go/spec"
)

// Emitter is a generic emitter. When an event occurs, the
// corresponding method will be called. An error will generally
// mean that it's not possible to write the output. A common
// case where this happen is where the output is redirected to
// a file on a full hard disk.
//
// See the documentation of the main package for more details
// on the sequence in which events may occur.
type Emitter interface {
	// OnStarting is emitted before attempting to start a test.
	OnStarting(test spec.TestKind) error

	// OnError is emitted if a test cannot start.
	OnError(test spec.TestKind, err error) error

	// OnConnected is emitted when we connected to the ndt7 server.
	OnConnected(test spec.TestKind, fqdn string) error

	// OnDownloadEvent is emitted during the download.
	OnDownloadEvent(m *spec.Measurement) error

	// OnUploadEvent is emitted during the upload.
	OnUploadEvent(m *spec.Measurement) error

	// OnComplete is always emitted when the test is over.
	OnComplete(test spec.TestKind) error

	// OnSummary is emitted after the test is over.
	OnSummary(s *Summary) error
}
