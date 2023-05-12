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
	workersManager := startWorkers(log.Log, sessionManager, conn)

	// wait for workers to terminate
	workersManager.WaitWorkersShutdown()
}
