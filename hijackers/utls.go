package hijackers

import (
	"crypto/tls"
	"fmt"
	utls "github.com/getlantern/utls"
	"io"
	"log"
	"net"
	"net/url"
	"time"
	"tls_mirror/utils"
)

type utlsHijacker struct {
	connSpecName     string
	allowInsecure    bool
	clientTLSConfig  *tls.Config
	remoteUTLSConfig *utls.Config
	generateCertFunc func(ips []string, names []string) (*tls.Certificate, error)
	dialTimeout      time.Duration
}

func NewUTLSHijacker(
	connSpecName string,
	allowInsecure bool,
	keyLogWriter io.Writer,
	generateCertFunc func(ips []string, names []string) (*tls.Certificate, error),
	dialTimeout time.Duration,
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
		dialTimeout:      dialTimeout,
	}
}

func (h *utlsHijacker) GetConns(url *url.URL, clientRaw net.Conn) (net.Conn, net.Conn, error) {
	var remoteConn net.Conn

	clientConnOrig, clientConnCopy := utils.NewTeeConn(clientRaw)

	fpCh := make(chan *fpResult, 1) // Buffered to prevent racy deadlock between Handshake and extractALPN
	alpnErrCh := make(chan error)
	clientConfigTemplate := h.clientTLSConfig.Clone()
	clientConfigTemplate.GetConfigForClient = h.clientHelloCallback(url, clientConfigTemplate, &remoteConn, fpCh, alpnErrCh)
	plaintextConn := tls.Server(clientConnOrig, clientConfigTemplate)
	_, err := clientConnOrig.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	if err != nil {
		return nil, nil, err
	}

	go h.extractALPN(clientConnCopy, fpCh, alpnErrCh)

	return plaintextConn, remoteConn, plaintextConn.Handshake() // Return connections so they can be closed
}

// fpRes is a container struct for client`s clientHello fingerprinting results
type fpResult struct {
	helloSpec  *utls.ClientHelloSpec
	nextProtos []string
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
func (h *utlsHijacker) clientHelloCallback(target *url.URL, clientConfigTemplate *tls.Config, remoteConnRes *net.Conn, alpnCh chan *fpResult, errCh chan error) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	return func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		log.Printf("Handshake callback")
		var hostname string
		if net.ParseIP(target.Hostname()) == nil {
			hostname = target.Hostname()
		}
		sni := info.ServerName
		// Timeout must be set. Otherwise, dialing will never succeed if the first address
		// returned by resolver is not responding (connection will just hang forever).
		d := net.Dialer{
			Timeout: h.dialTimeout,
		}
		remotePlaintextConn, err := d.Dial("tcp", target.Host)
		if err != nil {
			return nil, err
		}
		log.Printf("Remote conn established")
		needClose := true
		defer func() {
			if needClose {
				log.Printf("Closing remotePlaintextConn")
				remotePlaintextConn.Close()
			}
		}()
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

		var fpRes *fpResult

		log.Printf("Wait for extractALPN")
		select {
		case err := <-errCh:
			return nil, fmt.Errorf("error extracting ALPN: %v", err)
		case fpRes = <-alpnCh:
			break
		}
		log.Printf("Done extractALPN")

		remoteConn := utls.UClient(remotePlaintextConn, remoteConfig, utls.HelloCustom)
		*remoteConnRes = remoteConn // Pass connection back
		spec := fpRes.helloSpec
		if spec == nil {
			return nil, fmt.Errorf("invalid connection spec name %s", h.connSpecName)
		}
		if err := remoteConn.ApplyPreset(spec); err != nil {
			return nil, err
		}
		if sni != "" {
			remoteConn.SetSNI(sni)
		}
		log.Printf("Remote handshake")

		err = remoteConn.Handshake()
		if err != nil {
			return nil, err
		}

		clientConfig := clientConfigTemplate.Clone()
		clientConfig.GetConfigForClient = nil

		cs := remoteConn.ConnectionState()
		alpnRes := cs.NegotiatedProtocol
		if alpnRes != "" {
			// Hot-swap ALPN response for client
			clientConfig.NextProtos = []string{alpnRes}
		}

		log.Printf("Certificate generation")

		cert, err := generateCert(info, target.Hostname(), h.generateCertFunc)
		if err != nil {
			return nil, err
		}
		clientConfig.Certificates = []tls.Certificate{*cert}

		needClose = false
		return clientConfig, nil
	}
}

func (h *utlsHijacker) extractALPN(tlsRawCopy io.Reader, fpResCh chan *fpResult, errCh chan error) {
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
	clientHello := utls.UnmarshalClientHello(clientHelloBody)
	if clientHello == nil {
		errCh <- fmt.Errorf("failed to unmarshal clientHello")
		return
	}
	nextProtos := clientHello.AlpnProtocols
	log.Printf("Client ALPN offers: %v", nextProtos)

	f := utls.Fingerprinter{
		KeepPSK:           false,
		AllowBluntMimicry: true,
		AlwaysAddPadding:  false,
	}
	clientHelloSpec, err := f.FingerprintClientHello(append(tlsHeader, clientHelloBody...))
	if err != nil {
		log.Printf("Client hello fingerprinting error %v", err)
		errCh <- err
		return
	}
	log.Printf("Sending fpRes")
	fpResCh <- &fpResult{
		helloSpec:  clientHelloSpec,
		nextProtos: nextProtos,
	}

	log.Printf("Start sinking ALPN copy")
	_, err = io.Copy(io.Discard, tlsRawCopy) // Sink remaining data - we don't need them
	if err != nil {
		netOpError, ok := err.(*net.OpError)
		if ok && netOpError.Err.Error() != "use of closed network connection" {
			log.Printf("Sinking failed, error: %v", err)
			errCh <- err
		}
	}

	log.Printf("Sinking done, error: %v", err)
	return
}
