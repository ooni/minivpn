package emitter

/*
   Vendoring of m-lab's ndt7-client reference code, to be able to experiment
   and manipulate parts that are exposed as internal in the library.
   Upstream: https://github.com/m-lab/ndt7-client-go/

   SPDX-License-Identifier: Apache-2.0

   (c) Stephen Soltesz
   (c) Peter Boothe
   (c) Simone Basso
*/

// ValueUnitPair represents a {"Value": ..., "Unit": ...} pair.
type ValueUnitPair struct {
	Value float64
	Unit  string
}

// Summary is a struct containing the values displayed to the user at
// the end of an ndt7 test.
type Summary struct {
	// ServerFQDN is the FQDN of the server used for this test.
	ServerFQDN string

	// ServerIP is the (v4 or v6) IP address of the server.
	ServerIP string

	// ClientIP is the (v4 or v6) IP address of the client.
	ClientIP string

	// DownloadUUID is the UUID of the download test.
	// TODO: add UploadUUID after we start processing counterflow messages.
	DownloadUUID string

	// Download is the download speed, in Mbit/s. This is measured at the
	// receiver.
	Download ValueUnitPair

	// Upload is the upload speed, in Mbit/s. This is measured at the sender.
	Upload ValueUnitPair

	// DownloadRetrans is the retransmission rate. This is based on the TCPInfo
	// values provided by the server during a download test.
	DownloadRetrans ValueUnitPair

	// RTT is the round-trip time of the latest measurement, in milliseconds.
	// This is provided by the server during a download test.
	MinRTT ValueUnitPair
}

// NewSummary returns a new Summary struct for a given FQDN.
func NewSummary(FQDN string) *Summary {
	return &Summary{
		ServerFQDN: FQDN,
	}
}
