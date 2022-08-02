package main

import (
	"github.com/elazarl/goproxy"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"tls_mirror/hijackers"
)

func getTLSHijackFunc(hj hijackers.Hijacker) func(req *http.Request, connL net.Conn, ctx *goproxy.ProxyCtx) {
	return func(req *http.Request, connL net.Conn, ctx *goproxy.ProxyCtx) {
		var err error
		var tlsConnR net.Conn
		var closer sync.Once

		closeFunc := func() {
			ctx.Logf("[*] Connections closed")
			_ = connL.Close()
			_ = tlsConnR.Close()
		}

		tlsConnL, tlsConnR, err := hj.GetConns(req.URL, connL)
		if err != nil {
			ctx.Warnf("[x] Couldn't connect: %v", err)
			return
		}

		ctx.Logf("[*] Connected to server: %s\n", tlsConnR.RemoteAddr())

		go handleServerTLSConn(tlsConnR, tlsConnL, &closer)

		_, e := io.Copy(tlsConnR, tlsConnL)
		if e != nil && e != io.EOF {
			log.Printf("bad io.Copy [handleConnection]: %v", e)
		}

		closer.Do(closeFunc)
	}
}

func handleServerTLSConn(connR, connL net.Conn, closer *sync.Once) {
	closeFunc := func() {
		log.Println("[*] Connections closed.")
		_ = connL.Close()
		_ = connR.Close()
	}

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
