package main

import (
	"context"
	"net"
	"os"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/networkio"
	"github.com/ooni/minivpn/internal/session"
)

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

	// start all the workers
	workersManager := startWorkers(log.Log, sessionManager, conn, options)

	// wait for workers to terminate
	workersManager.WaitWorkersShutdown()
}
