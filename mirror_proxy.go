package main

import (
	"fmt"
	"github.com/elazarl/goproxy"
	http_dialer "github.com/fedosgad/go-http-dialer"
	"github.com/fedosgad/mirror_proxy/cert_generator"
	"github.com/fedosgad/mirror_proxy/hijackers"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
	"io"
	"log"
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
	defer klw.Close()

	cg, err := cert_generator.NewCertGeneratorFromFiles(opts.CertFile, opts.KeyFile)
	if err != nil {
		log.Fatal(err)
	}

	dialer, err := getDialer(opts)
	if err != nil {
		log.Fatalf("Error getting proxy dialer: %v", err)
	}

	clientTLsCredentials, err := getClientTLsCredentials(opts)
	if err != nil {
		log.Fatal(err)
	}

	hjf := hijackers.NewHijackerFactory(
		dialer,
		opts.AllowInsecure,
		klw,
		cg.GenChildCert,
		clientTLsCredentials,
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

type writeNopCloser struct {
	io.Writer
}

func (c writeNopCloser) Close() error {
	return nil
}

func getSSLLogWriter(opts *Options) (klw io.WriteCloser, err error) {
	klw = writeNopCloser{Writer: io.Discard}

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
		if proxyURL.User != nil {
			pass, _ := proxyURL.User.Password()
			username := proxyURL.User.Username()
			return http_dialer.New(
				proxyURL,
				http_dialer.WithProxyAuth(http_dialer.AuthBasic(username, pass)),
				http_dialer.WithConnectionTimeout(opts.ProxyTimeout),
				http_dialer.WithContextDialer(d),
			), nil
		}
		return http_dialer.New(
			proxyURL,
			http_dialer.WithConnectionTimeout(opts.ProxyTimeout),
			http_dialer.WithContextDialer(d),
		), nil
	}

	return nil, fmt.Errorf("cannot use proxy scheme %q", proxyURL.Scheme)
}

func getClientTLsCredentials(opts *Options) (*hijackers.ClientTLsCredentials, error) {
	if opts.HostWithMutualTLS == "" {
		return nil, nil
	}

	cert, err := os.ReadFile(opts.ClientCertFile)
	if err != nil {
		return nil, err
	}

	key, err := os.ReadFile(opts.ClientKeyFile)
	if err != nil {
		return nil, err
	}

	certificate, err := utls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}

	clientTLsCredentials := &hijackers.ClientTLsCredentials{
		Host: opts.HostWithMutualTLS,
		Cert: certificate,
	}
	return clientTLsCredentials, nil
}
