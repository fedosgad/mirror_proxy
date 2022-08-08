package main

import (
	"flag"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"tls_mirror/cert_generator"
	"tls_mirror/hijackers"
)

var reqCounter = 0

func main() {
	listenAddr := flag.String("l", ":8080", "Proxy listen address")
	connAddr := flag.String("a", "", "Connection target address")

	certFile := flag.String("c", "", "Certificate file")
	keyFile := flag.String("k", "", "Key file")
	keyLogFile := flag.String("f", "", "SSL/TLS key log file")
	fallbackCertTarget := flag.String("t", "", "Hostname/IP to use in certificate in case client provides no SNI")
	connSpecName := flag.String("p", "", "Connection profile to use")
	allowInsecure := flag.Bool("i", false, "Allow skipping server certificate validation")

	flag.Parse()

	var connUrl *url.URL
	if *connAddr != "" {
		var err error
		connUrl, err = url.Parse(*connAddr)
		if err != nil {
			log.Fatal(err)
		}
	}

	cg, err := cert_generator.NewCertGeneratorFromFiles(*certFile, *keyFile)
	if err != nil {
		log.Fatal(err)
	}

	keyLogWriter, err := getKeyLogWriter(*keyLogFile)
	if err != nil {
		log.Fatal(err)
	}

	hj := hijackers.NewUTLSHijacker(*connSpecName, *allowInsecure, keyLogWriter, cg.GenChildCert)

	l, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	log.Println("[*] Listening...")

	for {
		cl, err := l.Accept()
		if err != nil {
			log.Printf("server: accept: %v", err)
			break
		}
		log.Printf("[*] Accepted from: %s\n", cl.RemoteAddr())
		go handleTLSConn(cl, connUrl, hj)
		//go handleConnection(cl, *connAddr)
	}
}

func getKeyLogWriter(keyLogFile string) (io.Writer, error) {
	var keyLogWriter io.Writer
	var err error
	if keyLogFile != "" {
		keyLogWriter, err = os.OpenFile(keyLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
	}
	return keyLogWriter, nil
}
