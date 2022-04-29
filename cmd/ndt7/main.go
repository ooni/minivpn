package main

// Shows an example of how to pass the vpn Dialer to an ndt7 client to perform
// a download/upload measurement.

import (
	"log"
	"os"
	"time"

	//"github.com/pborman/getopt/v2"

	"github.com/ainghazal/minivpn/extras"
	"github.com/ainghazal/minivpn/extras/memoryless"
	//"github.com/ainghazal/minivpn/obfs4"
	"github.com/ainghazal/minivpn/vpn"
)

func wait(c memoryless.Config) {
	t, _ := memoryless.NewTimer(c)
	<-t.C
}

func main() {
	ndt7Server := os.Getenv("NDT7_SERVER")
	if ndt7Server == "" {
		log.Fatal("Set NDT7_SERVER variable")
	}
	provider := os.Getenv("PROVIDER")
	if provider == "" {
		log.Fatal("Set PROVIDER variable")
	}

	/*
		optExp := getopt.StringLong("type", 'e', "all", "Type of experiment (download, upload, [all])")
		optCnt := getopt.IntLong("count", 'c', 1, "Repetitions count (default: 1)")
		getopt.Parse()
	*/

	opts, err := vpn.ParseConfigFile("data/" + provider + "/config")
	if err != nil {
		panic(err)
	}

	var c memoryless.Config

	// one needs to be careful choosing the clamping,
	// but while debugging every second counts.
	// see https://github.com/m-lab/go/blob/master/memoryless/memoryless.go#L102

	if os.Getenv("DEBUG") == "1" {
		c = memoryless.Config{
			Expected: 10 * time.Second,
			Min:      5 * time.Second,
			Max:      15 * time.Second,
		}
	} else {
		c = memoryless.Config{
			Expected: 60 * time.Second,
			Min:      10 * time.Second,
			Max:      250 * time.Second,
		}
	}
	if err := c.Check(); err != nil {
		log.Fatal("error:", err.Error())
	}

	dialer := vpn.NewDialerFromOptions(opts)

	direct := false
	base := os.Getenv("BASE")
	if base == "1" {
		direct = true
	}

	extras.RunMeasurement(dialer, ndt7Server, "download", direct)
	//extras.RunMeasurement(dialer, ndt7Server, "upload", direct)

	/*
		for i := 1; i <= *optCnt; i++ {
			log.Println()
			log.Println("Run:", i)
			log.Println()

			dialer := vpn.NewDialerFromOptions(opts)

			if opts.ProxyOBFS4 != "" {
				log.Println("Using obfs4 proxy")
				node, err := obfs4.NewNodeFromURI(opts.ProxyOBFS4)
				if err != nil {
					log.Fatal(err)
				}
				obfs4.Obfs4ClientInit(node)
				dialFn := obfs4.Dialer(node.Addr)
				dialer.DialFn = vpn.DialFunc(dialFn)
			}
			if *optExp == "all" || *optExp == "download" {
				extras.RunMeasurement(dialer, ndt7Server, "download")
			}

			wait(c) // is the pasta ready?

			if *optExp == "all" || *optExp == "upload" {
				extras.RunMeasurement(dialer, ndt7Server, "upload")
			}
			if i != *optCnt {
				// we don't need to wait on the last run
				wait(c)
			}
		}
	*/
	// BUG I get a timeout when I try to run the two experiments reusing the same client. Is this the correct way of doing this?
	// {"Key":"error","Value":{"Test":"download","Failure":"dial: i/o timeout"}}
	// on the server side:
	// 2022/04/26 16:12:23 close.go:31: runMeasurement: ignoring conn.Close result (tls: failed to send closeNotify alert (but connection was closed anyway): write tcp [NDT7_SERVER_IP]:4443->[GW_IP]:36165: write: broken pipe)
}
