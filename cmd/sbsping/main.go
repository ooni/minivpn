package main

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"github.com/ooni/minivpn/vpn"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// "atomic Int64 and Add one
// but we're stuck with go1.18"
//
// 🎵🎵🎵🎵🎵🎵🎵🎵🎵🎵🎵
var (
	pingCounter int
	pingMu      sync.Mutex
)

func senderLoop(wg *sync.WaitGroup, conn net.Conn) {
	// synchronize with parent
	defer wg.Done()

	// logging messages
	log.Printf("sender running")
	defer log.Printf("sender done")

	for idx := 0; idx < 10; idx++ {
		// atomically obtain the sequence number to send
		pingMu.Lock()
		pingCounter++
		counter := pingCounter
		pingMu.Unlock()

		// create the ICMP message to send
		icmpMessage := &icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				Seq:  counter,
				Data: nil,
			},
		}
		payload, err := icmpMessage.Marshal(nil)
		if err != nil {
			log.Printf("icmpMessage.Marshal: %s", err.Error())
			break
		}

		// write the payload
		if _, err := conn.Write([]byte(payload)); err != nil {
			log.Printf("conn.Write: %s", err.Error())
			break
		}

		// log that we're sending data
		log.Printf("sent data: %d %+v", counter, payload)

		// wait before sending next ping
		time.Sleep(time.Second)
	}
}

func receiverLoop(wg *sync.WaitGroup, conn net.Conn) {
	// synchronize with parent
	defer wg.Done()

	// logging messages
	log.Printf("receiver running")
	defer log.Printf("receiver done")

	for {
		// read the incoming payload message
		buffer := make([]byte, 8000)
		count, err := conn.Read(buffer)
		if err != nil {
			log.Printf("conn.Read: %s", err.Error())
			break
		}
		payload := buffer[:count]

		// parse the received message as a ping reply
		replyPacket, err := icmp.ParseMessage(1, payload)
		if err != nil {
			log.Printf("icmp.ParseMessage: %s", err.Error())
			continue
		}
		pong, ok := replyPacket.Body.(*icmp.Echo)
		if !ok {
			log.Printf("not an icmp.Echo ping payload")
			continue
		}

		log.Printf("got data: %d %+v", pong.Seq, payload)
	}
}

func main() {
	// parse configuration file
	opts, err := vpn.NewOptionsFromFilePath("data/riseup/config")
	if err != nil {
		log.Fatal(err)
	}

	// create the OpenVPN client instance
	client := vpn.NewClientFromOptions(opts)

	// create the OpenVPN tunnel
	if err := client.Start(context.Background()); err != nil {
		log.Fatal(err)
	}

	// create network stack and virtual network device.
	stack, device, err := client.NewNetworkStack("8.8.8.8", "8.8.4.4")
	if err != nil {
		log.Fatal(err)
	}

	// bring the network device up.
	// TODO(bassosimone): how do we shut down the network device?
	device.Up()

	// create a new pinger
	conn, err := stack.Dial("ping4", "www.google.com")
	if err != nil {
		log.Fatal(err)
	}

	// spawn the sender
	senderWg := &sync.WaitGroup{}
	senderWg.Add(1)
	go senderLoop(senderWg, conn)

	// spawn the receiver
	receiverWg := &sync.WaitGroup{}
	receiverWg.Add(1)
	go receiverLoop(receiverWg, conn)

	// await for the sender to terminate
	senderWg.Wait()

	// close the connection
	conn.Close()

	// await for the receiver to terminate as well
	receiverWg.Wait()
}
