package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/apex/log"
	"github.com/pborman/getopt/v2"

	"github.com/ainghazal/minivpn/extras"
	"github.com/ainghazal/minivpn/vpn"
)

var (
	startTime = time.Now()
)

func printUsage() {
	fmt.Println("valid commands: ping, proxy")
	getopt.Usage()
	os.Exit(0)
}

// RunPinger takes an Option object, gets a Dialer, and runs a Pinger against
// the passed target, for count packets.
func RunPinger(opt *vpn.Options, target string, count uint32) error {
	conn := vpn.NewRawDialer(opt)
	pinger := extras.NewPinger(conn, target, int(count))
	err := pinger.Run()
	if err != nil {
		// TODO identify different errors
		os.Exit(42)
	}
	pinger.Stop()
	return nil
}

func main() {
	optConfig := getopt.StringLong("config", 'c', "", "Configuration file")
	optServer := getopt.StringLong("server", 's', "", "VPN Server to connect to")
	optTarget := getopt.StringLong("target", 't', "8.8.8.8", "Target for ICMP Ping")
	optCount := getopt.Uint32Long("count", 'n', uint32(3), "Stop after sending these many ECHO_REQUEST packets")
	optVerbosity := getopt.Uint16Long("verbosity", 'v', uint16(4), "Verbosity level (1 to 5, 1 is lowest)")

	helpFlag := getopt.Bool('h', "Display help")

	getopt.Parse()
	args := getopt.Args()

	if len(args) != 1 {
		printUsage()

	}

	if *helpFlag || (*optServer == "" && *optConfig == "") {
		printUsage()
	}

	var opts *vpn.Options

	verbosityLevel := log.InfoLevel
	switch *optVerbosity {
	case uint16(1):
		verbosityLevel = log.FatalLevel
	case uint16(2):
		verbosityLevel = log.ErrorLevel
	case uint16(3):
		verbosityLevel = log.WarnLevel
	case uint16(4):
		verbosityLevel = log.InfoLevel
	case uint16(5):
		verbosityLevel = log.DebugLevel
	default:
		verbosityLevel = log.DebugLevel
	}

	logger := &log.Logger{Level: verbosityLevel, Handler: &logHandler{Writer: os.Stderr}}
	logger.Debugf("config file: %s", *optConfig)

	opts, err := vpn.ParseConfigFile(*optConfig)
	if err != nil {
		fmt.Println("fatal: " + err.Error())
		os.Exit(1)
	}
	opts.Log = logger

	switch args[0] {
	case "ping":
		RunPinger(opts, *optTarget, *optCount)
	case "proxy":
		ListenAndServeSocks(opts)
	default:
		printUsage()
	}
}

type logHandler struct {
	io.Writer
}

func (h *logHandler) HandleLog(e *log.Entry) (err error) {
	var s string
	if e.Level == log.DebugLevel {
		s = fmt.Sprintf("%s", e.Message)
	} else if e.Level == log.ErrorLevel {
		s = fmt.Sprintf("[%14.6f] <!err> %s", time.Since(startTime).Seconds(), e.Message)
	} else {
		s = fmt.Sprintf("[%14.6f] <%s> %s", time.Since(startTime).Seconds(), e.Level, e.Message)
	}
	if len(e.Fields) > 0 {
		s += fmt.Sprintf(": %+v", e.Fields)
	}
	s += "\n"
	_, err = h.Writer.Write([]byte(s))
	return
}
