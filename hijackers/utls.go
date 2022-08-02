package hijackers

import (
	"crypto/tls"
	"fmt"
	utls "github.com/getlantern/utls"
	"io"
	"log"
	"net"
	"net/url"
	"tls_mirror/utils"
	"tls_mirror/utls_factory"
)

type utlsHijacker struct {
	connSpecName     string
	allowInsecure    bool
	clientTLSConfig  *tls.Config
	remoteUTLSConfig *utls.Config
	generateCertFunc func(ips []string, names []string) (*tls.Certificate, error)
}

func NewUTLSHijacker(
	connSpecName string,
	allowInsecure bool,
	keyLogWriter io.Writer,
	generateCertFunc func(ips []string, names []string) (*tls.Certificate, error),
) Hijacker {
	return &utlsHijacker{
		connSpecName:  connSpecName,
		allowInsecure: allowInsecure,
		clientTLSConfig: &tls.Config{
			KeyLogWriter: keyLogWriter,
		},
		remoteUTLSConfig: &utls.Config{
			KeyLogWriter: keyLogWriter,
		},
		generateCertFunc: generateCertFunc,
	}
}

func (h *utlsHijacker) GetConns(url *url.URL, clientConn net.Conn) (net.Conn, net.Conn, error) {
	var hostname string
	if net.ParseIP(url.Hostname()) == nil {
		hostname = url.Hostname()
	}

	clientConnOrig, clientConnCopy := utils.NewTeeConn(clientConn)

	var remoteConn net.Conn
	alpnCh := make(chan []string)
	alpnErrCh := make(chan error)
	clientConfig := h.clientTLSConfig.Clone()
	clientConfig.GetCertificate = h.clientHelloCallback(url, clientConfig, &remoteConn, alpnCh, alpnErrCh)
	plaintextConn := tls.Server(clientConnOrig, clientConfig)
	_, err := clientConnOrig.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	if err != nil {
		return nil, nil, err
	}

	go h.extractALPN(clientConnCopy, alpnCh, alpnErrCh)

	if err := plaintextConn.Handshake(); err != nil {
		return nil, nil, err
	}
	cs := plaintextConn.ConnectionState()
	sni := cs.ServerName

	remotePlaintextConn, err := net.Dial("tcp", url.Host)
	if err != nil {
		remotePlaintextConn.Close()
		return nil, nil, err
	}
	remoteConfig := h.remoteUTLSConfig.Clone()
	switch {
	case sni != "":
		remoteConfig.ServerName = sni
	case hostname != "":
		remoteConfig.ServerName = hostname
	default:
		if !h.allowInsecure {
			return nil, nil, fmt.Errorf("no SNI or name provided and InsecureSkipVerify == false")
		}
		remoteConfig.InsecureSkipVerify = true
	}

	return plaintextConn, remoteConn, err
}

// clientHelloCallback performs the following tasks:
//
// - get client ALPN offers
//
// - connect to and perform handshake with target server
//
// - set correct ALPN for client connection using  server response
//
// - generate certificate for client (according to client's SNI)
func (h *utlsHijacker) clientHelloCallback(
	target *url.URL,
	clientConfig *tls.Config,
	remoteConnRes *net.Conn,
	alpnCh chan []string,
	errCh chan error,
) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		var hostname string
		if net.ParseIP(target.Hostname()) == nil {
			hostname = target.Hostname()
		}
		sni := info.ServerName
		remotePlaintextConn, err := net.Dial("tcp", target.Host)
		if err != nil {
			return nil, err
		}
		remoteConfig := h.remoteUTLSConfig.Clone()
		switch {
		case sni != "":
			remoteConfig.ServerName = sni
		case hostname != "":
			remoteConfig.ServerName = hostname
		default:
			if !h.allowInsecure {
				return nil, fmt.Errorf("no SNI or name provided and InsecureSkipVerify == false")
			}
			remoteConfig.InsecureSkipVerify = true
		}

		var nextProtos []string

		select {
		case err := <-errCh:
			return nil, fmt.Errorf("error extracting ALPN: %v", err)
		case nextProtos = <-alpnCh:
			break
		}
		remoteConn := utls.UClient(remotePlaintextConn, remoteConfig, utls.HelloCustom)
		*remoteConnRes = remoteConn // Pass connection back
		spec := utls_factory.GetConnSpecWithALPN(h.connSpecName, nextProtos)
		if spec == nil {
			return nil, fmt.Errorf("invalid connection spec name %s", h.connSpecName)
		}
		if err := remoteConn.ApplyPreset(spec); err != nil {
			return nil, err
		}
		if sni != "" {
			remoteConn.SetSNI(sni)
		}
		err = remoteConn.Handshake()
		if err != nil {
			return nil, err
		}

		cs := remoteConn.ConnectionState()
		alpnRes := cs.NegotiatedProtocol
		if alpnRes != "" {
			// Hot-swap ALPN response for client
			clientConfig.NextProtos = []string{alpnRes}
		}

		return generateCert(info, target.Hostname(), h.generateCertFunc)
	}
}

func (h *utlsHijacker) extractALPN(tlsRawCopy io.Reader, resCh chan []string, errCh chan error) {
	tlsHeader := make([]byte, 5)
	n, err := io.ReadAtLeast(tlsRawCopy, tlsHeader, 5)
	if err != nil {
		if err == io.EOF {
			errCh <- fmt.Errorf("TLS header: unexpected EOF at byte %d", n)
			return
		}
		errCh <- fmt.Errorf("TLS header: read error: %v", err)
		return
	}
	if tlsHeader[0] != 0x16 {
		errCh <- fmt.Errorf("TLS header: incorrect header: %v", tlsHeader)
		return
	}
	log.Printf("TLS header bytes: %v", tlsHeader)
	clientHelloLength := uint16(tlsHeader[3])<<8 + uint16(tlsHeader[4])
	log.Printf("ClientHello length: %d", clientHelloLength)
	clientHelloBody := make([]byte, clientHelloLength)
	n, err = io.ReadAtLeast(tlsRawCopy, clientHelloBody, int(clientHelloLength))
	if err != nil {
		if err == io.EOF {
			errCh <- fmt.Errorf("TLS body: unexpected EOF at byte %d", n)
			return
		}
		errCh <- fmt.Errorf("TLS body: read error: %v", err)
		return
	}
	clientHello, err := utls.UnmarshalClientHello(clientHelloBody)
	if err != nil {
		errCh <- err
		return
	}
	nextProtos := clientHello.AlpnProtocols
	log.Printf("Client ALPN offers: %v", nextProtos)
	resCh <- nextProtos
	_, err = io.Copy(io.Discard, tlsRawCopy) // Sink remained data - we don't need them
	if err != nil {
		errCh <- err
	}
	return
}
