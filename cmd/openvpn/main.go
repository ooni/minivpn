package main

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/apex/log"
	"github.com/ooni/minivpn/extras/ping"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/networkio"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/tun"
)

func timeoutSecondsFromCount(count int) time.Duration {
	waitOnLastOne := 3 * time.Second
	return time.Duration(count)*time.Second + waitOnLastOne
}

func main() {
	log.SetLevel(log.DebugLevel)

	// parse the configuration file
	options, err := model.ReadConfigFile(os.Args[1])
	if err != nil {
		log.WithError(err).Fatal("NewOptionsFromFilePath")
	}
	log.Infof("parsed options: %s", options.ServerOptionsString())

	// TODO(ainghazal): move the initialization step to an early phase and keep a ref in the muxer
	if !options.HasAuthInfo() {
		log.Fatal("options are missing auth info")
	}
	// connect to the server
	dialer := networkio.NewDialer(log.Log, &net.Dialer{})
	ctx := context.Background()
	endpoint := net.JoinHostPort(options.Remote, options.Port)
	conn, err := dialer.DialContext(ctx, options.Proto.String(), endpoint)
	if err != nil {
		log.WithError(err).Fatal("dialer.DialContext")
	}

	// create a session
	sessionManager, err := session.NewManager(log.Log)
	if err != nil {
		log.WithError(err).Fatal("session.NewManager")
	}

	// create a tun Device
	// TODO(ainghazal): tun should be the OWNER of the connection
	tunnel := tun.NewTUN(sessionManager)

	// start all the workers
	workers := startWorkers(log.Log, sessionManager, tunnel, conn, options)
	// -----------------------------------------------------------------------
	// TODO(ainghazal): pass a specific channel to workers instead (tunClosed)
	tunnel.Workers = workers
	<-sessionManager.Ready

	pinger := ping.New("8.8.8.8", tunnel)
	count := 5
	pinger.Count = count

	err = pinger.Run(context.Background())
	if err != nil {
		pinger.PrintStats()
		log.WithError(err).Fatal("ping error")
	}
	pinger.PrintStats()

	// wait for workers to terminate
	workers.WaitWorkersShutdown()
}
