package main

import (
	"github.com/elazarl/goproxy"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"tls_mirror/cert_generator"
	"tls_mirror/hijackers"
)

func main() {
	opts := getOptions()

	klw := getSSLLogWriter(opts)
	cg, err := cert_generator.NewCertGeneratorFromFiles(opts.CertFile, opts.KeyFile)
	if err != nil {
		log.Fatal(err)
	}
	hjf := hijackers.NewHijackerFactory(
		opts.DialTimeout,
		opts.AllowInsecure,
		klw,
		cg.GenChildCert,
	)
	hj := hjf.Get(opts.Mode)

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
	proxy.Verbose = opts.Verbose

	if opts.PprofAddress != "" {
		go func() {
			log.Println(http.ListenAndServe(opts.PprofAddress, nil))
		}()
	}
	log.Fatal(http.ListenAndServe(opts.ListenAddress, proxy))
}

func getSSLLogWriter(opts *Options) io.Writer {
	klw := io.Discard
	if opts.SSLLogFile != "" {
		var err error
		klw, err = os.OpenFile(opts.SSLLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Error opening key log file: %v", err)
		}
	}
	return klw
}
