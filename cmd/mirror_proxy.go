package main

import (
	"fmt"
	"github.com/elazarl/goproxy"
	http_dialer "github.com/mwitkow/go-http-dialer"
	"golang.org/x/net/proxy"
	"io"
	"log"
	"mirror_proxy/cert_generator"
	"mirror_proxy/hijackers"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
)

func main() {
	opts := getOptions()

	klw, err := getSSLLogWriter(opts)
	if err != nil {
		log.Fatalf("Error opening key log file: %v", err)
	}
	cg, err := cert_generator.NewCertGeneratorFromFiles(opts.CertFile, opts.KeyFile)
	if err != nil {
		log.Fatal(err)
	}
	dialer, err := getDialer(opts)
	if err != nil {
		log.Fatalf("Error getting proxy dialer: %v", err)
	}
	hjf := hijackers.NewHijackerFactory(
		dialer,
		opts.AllowInsecure,
		klw,
		cg.GenChildCert,
	)
	hj := hjf.Get(opts.Mode)

	p := goproxy.NewProxyHttpServer()
	// Handle all CONNECT requests
	p.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*$"))).
		HandleConnect(goproxy.FuncHttpsHandler(
			func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
				return &goproxy.ConnectAction{
					Action: goproxy.ConnectHijack,
					Hijack: getTLSHijackFunc(hj),
				}, host
			}))
	p.Verbose = opts.Verbose

	if opts.PprofAddress != "" {
		go func() {
			log.Println(http.ListenAndServe(opts.PprofAddress, nil))
		}()
	}
	log.Fatal(http.ListenAndServe(opts.ListenAddress, p))
}

func getSSLLogWriter(opts *Options) (io.Writer, error) {
	var err error
	klw := io.Discard
	if opts.SSLLogFile != "" {
		klw, err = os.OpenFile(opts.SSLLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	return klw, err
}

func getDialer(opts *Options) (proxy.Dialer, error) {
	// Timeout SHOULD be set. Otherwise, dialing will never succeed if the first address
	// returned by resolver is not responding (connection will just hang forever).
	d := &net.Dialer{
		Timeout: opts.DialTimeout,
	}
	if opts.ProxyAddr == "" {
		return d, nil
	}
	proxyURL, err := url.Parse(opts.ProxyAddr)
	if err != nil {
		return nil, err
	}
	if proxyURL.Scheme == "socks5" {
		return proxy.FromURL(proxyURL, d)
	}
	if proxyURL.Scheme == "http" || proxyURL.Scheme == "https" {
		// TODO(fgruzdev): add context support to http_dialer
		if proxyURL.User != nil {
			pass, _ := proxyURL.User.Password()
			username := proxyURL.User.Username()
			return http_dialer.New(
				proxyURL,
				http_dialer.WithProxyAuth(http_dialer.AuthBasic(username, pass)),
				http_dialer.WithConnectionTimeout(opts.ProxyTimeout),
				http_dialer.WithDialer(d),
			), nil
		}
		return http_dialer.New(
			proxyURL,
			http_dialer.WithConnectionTimeout(opts.ProxyTimeout),
			http_dialer.WithDialer(d),
		), nil
	}

	return nil, fmt.Errorf("cannot use proxy scheme %q", proxyURL.Scheme)
}
