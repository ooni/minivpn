package extras

/*
   Vendoring of m-lab's ndt7-client reference code, to be able to experiment
   and manipulate parts that are exposed as internal in the library.
   Upstream: https://github.com/m-lab/ndt7-client-go/

   SPDX-License-Identifier: Apache-2.0

   (c) Stephen Soltesz
   (c) Peter Boothe
   (c) Simone Basso
   (c) Ain Ghazal
*/

import (
	"context"
	"crypto/tls"
	"log"
	"os"
	"time"

	"github.com/gorilla/websocket"
	"github.com/m-lab/ndt7-client-go"
	"github.com/m-lab/ndt7-client-go/spec"
	"github.com/ooni/minivpn/extras/ndt7/emitter"
	"github.com/ooni/minivpn/vpn"
)

const (
	clientName     = "minivpn-ndt7-client"
	clientVersion  = "0.6.1"
	defaultTimeout = 10 * time.Second
)

type runner struct {
	client  *ndt7.Client
	emitter emitter.Emitter
}

func (r runner) runDownload(ctx context.Context) int {
	return r.runTest(ctx, spec.TestDownload, r.client.StartDownload,
		r.emitter.OnDownloadEvent)
}

func (r runner) runUpload(ctx context.Context) int {
	return r.runTest(ctx, spec.TestUpload, r.client.StartUpload,
		r.emitter.OnUploadEvent)
}

func (r runner) runTest(
	ctx context.Context, test spec.TestKind,
	start func(context.Context) (<-chan spec.Measurement, error),
	emitEvent func(m *spec.Measurement) error,
) int {
	// Implementation note: we want to always emit the initial and the
	// final events regardless of how the actual test goes. What's more,
	// we want the exit code to be nonzero in case of any error.
	err := r.emitter.OnStarting(test)
	if err != nil {
		return 1
	}
	code := r.doRunTest(ctx, test, start, emitEvent)
	err = r.emitter.OnComplete(test)
	if err != nil {
		return 1
	}
	return code
}

func (r runner) doRunTest(
	ctx context.Context, test spec.TestKind,
	start func(context.Context) (<-chan spec.Measurement, error),
	emitEvent func(m *spec.Measurement) error,
) int {
	ch, err := start(ctx)
	if err != nil {
		_ = r.emitter.OnError(test, err)
		return 1
	}
	err = r.emitter.OnConnected(test, r.client.FQDN)
	if err != nil {
		return 1
	}
	for ev := range ch {
		err = emitEvent(&ev)
		if err != nil {
			return 1
		}
	}
	return 0
}

// TODO use memoryless to repeat measurements, gather the json outputs and
// return a measurement batch.

// RunMeasurement performs a download & upload measurement against a given ndt7 server.
// It expects a vpn Dialer and a server string (ip:port).
// If the direct parameter is set to true, the vpn Dialer will not be used and
// a direct connection will be used instead.
func RunMeasurement(d vpn.TunDialer, ndt7Server string, mode string, direct bool) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	var r runner

	insecureTLS := false
	if os.Getenv("TLS_NOVERIFY") == "1" {
		insecureTLS = true
	}

	vpnDialer := websocket.Dialer{
		// TODO(ainghazal): pass a config flag to force the InsecureSkipVerify config,
		// this should not be used in production.
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureTLS,
		},
	} //#nosec G402
	if direct == false {
		vpnDialer.NetDialContext = d.DialContext
	} else {
		log.Println("using a direct connection to ndt7 server")
	}

	r.client = ndt7.NewClient(clientName, clientVersion)
	r.client.Server = ndt7Server
	r.client.Dialer = vpnDialer
	r.emitter = emitter.NewJSON(os.Stdout)
	switch mode {
	case "download":
		r.runDownload(ctx)
	case "upload":
		r.runUpload(ctx)
	}
}
