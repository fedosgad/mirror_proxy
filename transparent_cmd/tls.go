package main

import (
	"io"
	"log"
	"mirror_proxy/hijackers"
	"net"
	"net/url"
	"sync"
)

func handleTLSConn(connL net.Conn, fallbackTarget *url.URL, hj hijackers.Hijacker) {
	var err error
	var tlsConnR net.Conn
	var closer sync.Once

	closeFunc := func() {
		log.Println("[*] Connections closed")
		_ = connL.Close()
		_ = tlsConnR.Close()
	}

	tlsConnL, tlsConnR, err := hj.GetConns(fallbackTarget, connL, nil)
	if err != nil {
		log.Printf("[x] Couldn't connect: %v", err)
		return
	}

	log.Printf("[*][%d] Connected to server: %s\n", reqCounter, tlsConnR.RemoteAddr())

	// setup handler to read from server and print to screen
	go handleServerTLSConn(tlsConnR, tlsConnL, &closer)

	//r, w := io.Pipe()
	//tee := io.MultiWriter(tlsConnR, w)

	//go discardData(r)
	//go dumpData(r, "CLIENT", reqCounter)
	reqCounter++

	//_, e := io.Copy(tee, tlsConnL)
	_, e := io.Copy(tlsConnR, tlsConnL)
	if e != nil && e != io.EOF {
		log.Printf("bad io.Copy [handleConnection]: %v", e)
	}

	closer.Do(closeFunc)
}

func handleServerTLSConn(connR, connL net.Conn, closer *sync.Once) {
	closeFunc := func() {
		log.Println("[*] Connections closed.")
		_ = connL.Close()
		_ = connR.Close()
	}

	//r, w := io.Pipe()
	//tee := io.MultiWriter(connL, w)
	//go discardData(r)
	//go dumpData(r, "SERVER", id)
	//_, e := io.Copy(tee, connR)

	_, e := io.Copy(connL, connR)

	if e != nil && e != io.EOF {
		// check if error is about the closed connection
		// this is expected in most cases, so don't make a noise about it
		netOpError, ok := e.(*net.OpError)
		if ok && netOpError.Err.Error() != "use of closed network connection" {
			log.Printf("bad io.Copy [handleServerMessage]: %v", e)
		}
	}

	closer.Do(closeFunc)
}
