package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"regexp"
	"time"
	"tls_mirror/cert_generator"
	"tls_mirror/hijackers"

	"github.com/elazarl/goproxy"
)

func main() {
	verbose := flag.Bool("v", false, "Log every proxy request to stdout")
	tlsPassthrough := flag.Bool("n", false, "Do not MITM TLS connections")
	allowInsecure := flag.Bool("i", false, "Allow skipping server certificate validation")
	addr := flag.String("a", ":8080", "Proxy listen address")
	certFile := flag.String("c", "", "Certificate file")
	keyFile := flag.String("k", "", "Key file")
	keyLogFile := flag.String("l", "", "SSL/TLS key log file")
	fallbackCertTarget := flag.String("t", "", "Hostname/IP to use in certificate in case client provides no SNI")
	connSpecName := flag.String("p", "", "Connection profile to use")
	dialTimeout := flag.Duration("dt", 5*time.Second, "Request dial timeout")
	flag.Parse()

	var hj hijackers.Hijacker
	switch {
	case *tlsPassthrough:
		hj = hijackers.NewPassThroughHijacker(*dialTimeout)
	default:
		hj = getUtlsHijacker(*certFile, *keyFile, *keyLogFile, *fallbackCertTarget, *connSpecName, *allowInsecure, *dialTimeout)
	}

	proxy := goproxy.NewProxyHttpServer()
	// Handle all CONNECT requests
	proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*$"))).
		HandleConnect(goproxy.FuncHttpsHandler(
			func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
				return &goproxy.ConnectAction{
					Action: goproxy.ConnectHijack,
					Hijack: getTLSHijackFunc(hj),
				}, host
			}))
	proxy.Verbose = *verbose

	go func() { // profiling
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
	log.Fatal(http.ListenAndServe(*addr, proxy))
}

func getUtlsHijacker(
	certFile, keyFile, keyLogFile, fallbackCertTarget, connSpecName string,
	allowInsecure bool,
	dialTimeout time.Duration,
) hijackers.Hijacker {
	var certs []tls.Certificate

	if certFile == "" || keyFile == "" {
		log.Fatal("Certificate and key files required when performing MITM")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("Error loading certificate files: %v", err)
	}
	certs = []tls.Certificate{cert}

	var keyLogWriter io.Writer
	if keyLogFile != "" {
		var err error
		keyLogWriter, err = os.OpenFile(keyLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Error opening key log file: %v", err)
		}
	}
	cg, err := cert_generator.NewCertGenerator(certs[0], fallbackCertTarget)
	if err != nil {
		log.Fatalf("Error creating certificate generator: %v", err)
	}

	return hijackers.NewUTLSHijacker(connSpecName, allowInsecure, keyLogWriter, cg.GenChildCert, dialTimeout)
}
