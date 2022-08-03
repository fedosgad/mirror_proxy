package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"sync"
	"tls_mirror/cert_generator"
	"tls_mirror/hijackers"
)

func handleTunneling(w http.ResponseWriter, r *http.Request, hj hijackers.Hijacker) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	defer clientConn.Close()

	clientPlaintext, remotePlaintext, err := hj.GetConns(r, clientConn)
	if err != nil {
		return
	}

	wg := &sync.WaitGroup{}
	go transfer(clientPlaintext, remotePlaintext, wg)
	go transfer(remotePlaintext, clientPlaintext, wg)
	wg.Wait()
}
func transfer(destination io.WriteCloser, source io.ReadCloser, wg *sync.WaitGroup) {
	defer destination.Close()
	defer source.Close()
	wg.Add(1)
	n, err := io.Copy(destination, source)
	if err != nil {
		log.Printf("transfer error at byte %d: %v", n, err)
	}
	wg.Done()
}
func handleHTTP(w http.ResponseWriter, req *http.Request) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	n, err := io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("handleHTTP error at byte %d: %v", n, err)
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

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
	flag.Parse()

	_ = verbose

	var hj hijackers.Hijacker
	switch {
	case *tlsPassthrough:
		hj = hijackers.NewPassThroughHijacker(0)
	default:
		hj = getUtlsHijacker(*certFile, *keyFile, *keyLogFile, *fallbackCertTarget, *connSpecName, *allowInsecure)
	}
	_ = hj

	server := &http.Server{
		Addr: *addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r, hj)
			} else {
				handleHTTP(w, r)
			}
		}),
	}

	go func() { // profiling
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	log.Fatal(server.ListenAndServe())
}

func getUtlsHijacker(certFile, keyFile, keyLogFile, fallbackCertTarget, connSpecName string, allowInsecure bool) hijackers.Hijacker {
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

	return hijackers.NewUTLSHijacker(connSpecName, allowInsecure, keyLogWriter, cg.GenChildCert)
}
