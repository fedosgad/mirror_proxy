package main

import (
	"bufio"
	"fmt"
	"github.com/elazarl/goproxy"
	"io"
	"net"
	"net/http"
	"time"
	"tls_mirror/hijackers"
)

const flushInterval = 100 * time.Millisecond

func getTLSHijackFunc(hj hijackers.Hijacker) func(req *http.Request, client net.Conn, ctx *goproxy.ProxyCtx) {
	return func(req *http.Request, client net.Conn, ctx *goproxy.ProxyCtx) {
		defer func() {
			if e := recover(); e != nil {
				ctx.Logf("error connecting to remote: %v", e)
				client.Write([]byte("HTTP/1.1 500 Cannot reach destination\r\n\r\n"))
			}
			client.Close()
		}()

		clientPlaintext, remotePlaintext, err := hj.GetConns(req, client)
		orPanic(err)
		clientBuf := bufio.NewReadWriter(bufio.NewReader(clientPlaintext), bufio.NewWriter(clientPlaintext))
		remoteBuf := bufio.NewReadWriter(bufio.NewReader(remotePlaintext), bufio.NewWriter(remotePlaintext))

		flushClose := func(buf *bufio.ReadWriter, conn net.Conn) {
			err := buf.Flush()
			orPanic(err)
			err = conn.Close()
			orPanic(err)
		}

		defer flushClose(remoteBuf, remotePlaintext)
		defer flushClose(clientBuf, clientPlaintext)

		errChan := make(chan error)
		done := make(chan struct{})

		connectLoop := func(dst io.Writer, src io.Reader, errTag string) {
			n, err := io.Copy(dst, src)
			if err != nil {
				errChan <- fmt.Errorf("%s: copy error on byte %d: %v", errTag, n, err)
				return
			}
		}

		flushLoop := func(buf *bufio.ReadWriter, errTag string) {
			ticker := time.NewTicker(flushInterval)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					err := buf.Flush()
					if err != nil {
						errChan <- fmt.Errorf("%s: flush err: %v", errTag, err)
						return
					}
				}
			}
		}

		go connectLoop(clientBuf, remoteBuf, "remote->client")
		go connectLoop(remoteBuf, clientBuf, "client->remote")
		//go connectLoop(clientPlaintext, remotePlaintext, "remote->client")
		//go connectLoop(remotePlaintext, clientPlaintext, "client->remote")
		go flushLoop(clientBuf, "client flush")
		go flushLoop(remoteBuf, "remote flush")

		select {
		case err := <-errChan:
			close(done)
			orPanic(err)
		case <-done:
		}

	}
}
