package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

func handleConnection(connL net.Conn, target string) {
	var err error
	var connR net.Conn
	var closer sync.Once

	// make sure connections get closed
	closeFunc := func() {
		log.Println("[*] Connections closed")
		_ = connL.Close()
		_ = connR.Close()
	}

	connR, err = net.Dial("tcp", target)
	if err != nil {
		log.Printf("[x] Couldn't connect: %v", err)
		return
	}
	log.Printf("[*][%d] Connected to server: %s\n", reqCounter, connR.RemoteAddr())

	// setup handler to read from server and print to screen
	go handleServerMessage(connR, connL, &closer)

	// setup a pipe that will allow writing to the output (stdout) writer, without
	// consuming the data
	r, w := io.Pipe()

	// create a MultiWriter which allows writing to multiple writers at once.
	// this means each read from the client, will result in a write to both the server writer and the pipe writer,
	// which then gets sent to the "dumpData" reader, which will output it to the screen
	// directly pass connR (server) into the multiwriter. There is no need to allocate a new io.Writer(connR)
	tee := io.MultiWriter(connR, w)

	// background the dumping of data to screen
	go discardData(r)
	//go dumpData(r, "CLIENT", reqCounter)
	reqCounter++

	// consume all data and forward between connections in memory
	// directly pass connL (client) into the io.Copy as the reader. There is no need to create a new io.Reader(connL)
	_, e := io.Copy(tee, connL)
	if e != nil && e != io.EOF {
		fmt.Printf("bad io.Copy [handleConnection]: %v", e)
	}

	// ensure connections are closed. With the sync, this will either happen here
	// or in the handleServerMessage function
	closer.Do(closeFunc)
}

func handleServerMessage(connR, connL net.Conn, closer *sync.Once) {
	// see comments in handleConnection
	// this is the same, just inverse, reads from server, writes to client
	closeFunc := func() {
		fmt.Println("[*] Connections closed.")
		_ = connL.Close()
		_ = connR.Close()
	}

	r, w := io.Pipe()
	tee := io.MultiWriter(connL, w)
	go discardData(r)
	//go dumpData(r, "SERVER", id)
	_, e := io.Copy(tee, connR)

	if e != nil && e != io.EOF {
		// check if error is about the closed connection
		// this is expected in most cases, so don't make a noise about it
		netOpError, ok := e.(*net.OpError)
		if ok && netOpError.Err.Error() != "use of closed network connection" {
			fmt.Printf("bad io.Copy [handleServerMessage]: %v", e)
		}
	}

	// ensure connections are closed. With the sync, this will either happen here
	// or in the handleConnection function
	closer.Do(closeFunc)
}
