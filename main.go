package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/apex/log"
	"github.com/pborman/getopt/v2"

	"github.com/ooni/minivpn/extras/ping"
	"github.com/ooni/minivpn/vpn"
)

var (
	startTime           = time.Now()
	extraTimeoutSeconds = 10 * time.Second
)

func printUsage() {
	fmt.Println("valid commands: ping, proxy")
	getopt.Usage()
	os.Exit(0)
}

func timeoutSecondsFromCount(count int) time.Duration {
	waitOnLastOne := 2 * time.Second
	return time.Duration(count)*time.Second + waitOnLastOne

}

// RunPinger takes an Option object, starts a Client, and runs a Pinger against
// the passed target, for a number count of packets.
func RunPinger(opt *vpn.Options, target string, count uint32) error {
	c := int(count)
	ctx, cancel := context.WithTimeout(context.Background(), timeoutSecondsFromCount(c)+extraTimeoutSeconds)
	defer cancel()

	tunnel := vpn.NewClientFromOptions(opt)
	if err := tunnel.Start(ctx); err != nil {
		return err
	}

	pinger := ping.New(target, tunnel)
	pinger.Count = c
	pinger.Timeout = timeoutSecondsFromCount(c)
	if err := pinger.Run(ctx); err != nil {
		return err
	}
	pinger.PrintStats()

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

	opts, err := vpn.NewOptionsFromFilePath(*optConfig)
	if err != nil {
		fmt.Println("fatal: " + err.Error())
		os.Exit(1)
	}
	opts.Log = logger

	switch args[0] {
	case "ping":
		err = RunPinger(opts, *optTarget, *optCount)
		if err != nil {
			logger.Error(err.Error())
		}
	case "proxy":
		// not actively tested at the moment
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
