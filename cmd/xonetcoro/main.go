package main

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/ooni/minivpn/netcoro"
)

func runWithTLSConn(conn *tls.Conn) {
	txp := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return conn, nil
		},
	}
	client := &http.Client{
		Transport: txp,
	}
	resp, err := client.Get("https://dns.google/")
	if err != nil {
		log.Printf("[https] client.Get failed: %s", err.Error())
		return
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[https] io.ReadAll failed: %s", err.Error())
		return
	}
	log.Printf("%s\n", string(respBody))
}

func runWithChildConn(conn net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	config := &tls.Config{
		ServerName: "dns.google",
	}
	tlsConn := tls.Client(conn, config)
	runWithTLSConn(tlsConn)
}

func reader(conn net.Conn, datach chan<- []byte, donech <-chan any, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		buffer := make([]byte, 8000)
		count, err := conn.Read(buffer)
		if err != nil {
			log.Printf("[reader] conn.Read: %s", err.Error())
			return
		}
		log.Printf("[reader] received %d bytes", count)
		data := buffer[:count]
		select {
		case datach <- data:
		case <-donech:
			return
		}
	}
}

func writer(conn net.Conn, datach <-chan []byte, donech <-chan any, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case data := <-datach:
			log.Printf("[writer] requested to write %d bytes", len(data))
			if _, err := conn.Write(data); err != nil {
				log.Printf("[reader] conn.Write: %s", err.Error())
				return
			}
		case <-donech:
			return
		}
	}
}

func main() {
	conn, err := net.Dial("tcp", "8.8.8.8:443")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	wg := &sync.WaitGroup{}

	directionUp := make(chan []byte)
	directionDown := make(chan []byte)
	finished := make(chan any)

	wg.Add(1)
	go reader(conn, directionUp, finished, wg) // writes directionUp

	wg.Add(1)
	go writer(conn, directionDown, finished, wg) // reads directionDown

	coro := netcoro.NewConn(directionUp, directionDown)
	wg.Add(1)
	go runWithChildConn(coro, wg)

	wg.Wait()
}
