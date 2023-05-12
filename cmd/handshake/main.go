package main

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/apex/log"
	"github.com/ooni/minivpn/openvpn"
)

func main() {
	log.Info("C_NOTHING")

	// read the configuation file
	options, err := openvpn.ReadConfigFile(os.Args[1])
	if err != nil {
		log.WithError(err).Fatal("NewOptionsFromFilePath")
	}
	log.Infof("parsed options: %s", options.ServerOptionsString())

	// connect to the server
	dialer := openvpn.NewDialer(log.Log, &net.Dialer{})
	ctx := context.Background()
	endpoint := net.JoinHostPort(options.Remote, options.Port)
	conn, err := dialer.DialContext(ctx, options.Proto.String(), endpoint)
	if err != nil {
		log.WithError(err).Fatal("dialer.DialContext")
	}
	log.Infof("established connection: %s", conn.RemoteAddr().String())

	// create a session
	session, err := openvpn.NewSession()
	if err != nil {
		log.WithError(err).Fatal("NewSession")
	}
	_ = session

	// create a coordinator for all the layers
	coord := openvpn.NewCoordinator()

	// create the network loop
	nl := openvpn.NewNetworkLoop(coord, log.Log, conn)
	defer nl.Close()

	// create the reliable transport
	rt := openvpn.NewReliableTransport(
		coord,
		log.Log,
		session,
		nl.Incoming(),
		nl.Outgoing(),
	)

	/*
		log.Info("C_RESET")

		// create HARD_RESET packet
		pkt, err := openvpn.NewControlPacket(session, openvpn.P_CONTROL_HARD_RESET_CLIENT_V2, 0, nil)
		if err != nil {
			log.WithError(err).Fatal("NewControlPacket")
		}

		// send HARD_RESET packet
		select {
		case rt.Outgoing() <- pkt:
		case <-coord.ShouldWorkerHangup():
			log.Warn("HANGUP")
			coord.AwaitCompleteShutdown(context.Background())
			return
		}

		log.Info("C_WAIT_RESET")

		// receive a packet that should be a HARD_RESET as well
		select {
		case pkt = <-rt.Incoming():
			log.Infof("%+v", pkt)
		case <-coord.ShouldWorkerHangup():
			log.Warn("HANGUP")
			coord.AwaitCompleteShutdown(context.Background())
			return
		}

		if pkt.Opcode != openvpn.P_CONTROL_HARD_RESET_SERVER_V2 {
			// TODO: we should loop here
			log.Fatal("invalid packet type!!!!!!!!")
		}
		if pkt.RemoteSessionID != session.LocalSessionID() {
			// TODO: we should loop here
			log.Fatal("not a packet for us!!!")
		}
		session.SetRemoteSessionID(pkt.LocalSessionID) // note: server's PoV!

		// TODO: is there a ACK for us? We're currently assuming that
		// the server will always send us ACKs in the RST response

		pkt = openvpn.NewACKForPacket(session, pkt)

		select {
		case rt.Outgoing() <- pkt:
		case <-coord.ShouldWorkerHangup():
			log.Warn("HANGUP")
			coord.AwaitCompleteShutdown(context.Background())
			return
		}
	*/

	pl := openvpn.NewProtocolLayer(
		coord,
		log.Log,
		options,
		session,
		rt.Incoming(),
		rt.Outgoing(),
	)

	pl.StartHandshake()

	// XXX: horrible hack
	<-time.After(5 * time.Second)

	/*
		const (
			stNothing = iota
			stControlChannelOpen
			stControlMessageSent
			stKeyExchanged
			stPullRequestSent
			stOptionsPushed
			stInitialized
			stDataReady
		)
	*/

	// parse the incoming HARD_RESET packet

	// shutdown everything
	coord.BroadcastAllWorkersShutdown()
	coord.AwaitCompleteShutdown(context.Background())
}
