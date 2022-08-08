package main

import (
	"github.com/elazarl/goproxy"
	"io"
	"net"
	"net/http"
	"sync"
	"tls_mirror/hijackers"
	"tls_mirror/utils"
)

func getTLSHijackFunc(hj hijackers.Hijacker) func(*http.Request, net.Conn, *goproxy.ProxyCtx) {
	return func(req *http.Request, connL net.Conn, ctx *goproxy.ProxyCtx) {
		var err error
		var tlsConnR net.Conn
		var closer sync.Once

		closeFunc := func() {
			ctx.Logf("Connections closed")
			_ = connL.Close()
			_ = tlsConnR.Close()
		}

		tlsConnL, tlsConnR, err := hj.GetConns(req.URL, connL, nil)
		if err != nil {
			ctx.Warnf("Couldn't connect: %v", err)
			return
		}

		ctx.Logf("Connected to server: %s\n", tlsConnR.RemoteAddr())

		go handleServerTLSConn(tlsConnR, tlsConnL, &closer, ctx)

		_, err = io.Copy(tlsConnR, tlsConnL)
		if err != nil && !utils.IsClosedConnErr(err) {
			ctx.Logf("bad io.Copy [handleConnection]: %v", err)
		}

		closer.Do(closeFunc)
	}
}

func handleServerTLSConn(connR, connL net.Conn, closer *sync.Once, ctx *goproxy.ProxyCtx) {
	closeFunc := func() {
		ctx.Logf("Connections closed.")
		_ = connL.Close()
		_ = connR.Close()
	}

	_, err := io.Copy(connL, connR)

	// check if error is about the closed connection
	// this is expected in most cases, so don't make a noise about it
	if err != nil && !utils.IsClosedConnErr(err) {
		ctx.Warnf("bad io.Copy [handleServerMessage]: %v", err)
	}

	closer.Do(closeFunc)
}
