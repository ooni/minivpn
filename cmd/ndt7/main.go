package main

// Shows an example of how to pass the vpn Dialer to an ndt7 client to perform
// a download/upload measurement.

import (
	"os"

	"github.com/ainghazal/minivpn/extras"
	"github.com/ainghazal/minivpn/vpn"
)

func main() {
	// TODO fail if no server provided
	ndt7Server := os.Getenv("SERVER")

	opts, err := vpn.ParseConfigFile("data/calyx/config")
	if err != nil {
		panic(err)
	}
	// TODO pass number of repetitions as a param and use memoryless lib
	// for exponential waiting between samples.
	dialer := vpn.NewDialerFromOptions(opts)
	// BUG I get a timeout when I try to run the two experiments reusing the same client. Is this the correct way of doing this?
	// {"Key":"error","Value":{"Test":"download","Failure":"dial: i/o timeout"}}
	// on the server side:
	// 2022/04/26 16:12:23 close.go:31: runMeasurement: ignoring conn.Close result (tls: failed to send closeNotify alert (but connection was closed anyway): write tcp [NDT7_SERVER_IP]:4443->[GW_IP]:36165: write: broken pipe)
	extras.RunMeasurement(dialer, ndt7Server, "download")
	extras.RunMeasurement(dialer, ndt7Server, "upload")
}
