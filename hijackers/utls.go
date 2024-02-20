package hijackers

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"

	"github.com/fedosgad/mirror_proxy/utils"
	utls "github.com/refraction-networking/utls"
)

type utlsHijacker struct {
	dialer               Dialer
	allowInsecure        bool
	clientTLSConfig      *tls.Config
	remoteUTLSConfig     *utls.Config
	generateCertFunc     func(ips []string, names []string) (*tls.Certificate, error)
	clientTLsCredentials *ClientTLsCredentials
}

func NewUTLSHijacker(
	dialer Dialer,
	allowInsecure bool,
	keyLogWriter io.Writer,
	generateCertFunc func(ips []string, names []string) (*tls.Certificate, error),
	clientTlsCredentials *ClientTLsCredentials,
) Hijacker {
	return &utlsHijacker{
		dialer:        dialer,
		allowInsecure: allowInsecure,
		clientTLSConfig: &tls.Config{
			KeyLogWriter: keyLogWriter,
		},
		remoteUTLSConfig: &utls.Config{
			KeyLogWriter: keyLogWriter,
		},
		generateCertFunc:     generateCertFunc,
		clientTLsCredentials: clientTlsCredentials,
	}
}

func (h *utlsHijacker) GetConns(target *url.URL, clientRaw net.Conn, ctxLogger Logger) (net.Conn, net.Conn, error) {
	var remoteConn net.Conn

	clientConnOrig, clientConnCopy := utils.NewTeeConn(clientRaw)

	f := clientHelloFingerprinter{
		conn:  clientConnCopy,
		fpCh:  make(chan *fpResult, 1),
		errCh: make(chan error, 1),
		log:   ctxLogger,
	}
	clientConfigTemplate := h.clientTLSConfig.Clone()
	clientConfigTemplate.GetConfigForClient = h.clientHelloCallback(target, clientConfigTemplate, &remoteConn, f, ctxLogger)
	plaintextConn := tls.Server(clientConnOrig, clientConfigTemplate)
	_, err := clientConnOrig.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	if err != nil {
		return nil, nil, err
	}

	go f.extractALPN()

	return plaintextConn, remoteConn, plaintextConn.Handshake() // Return connections so they can be closed
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
	clientConfigTemplate *tls.Config,
	remoteConnRes *net.Conn,
	chf clientHelloFingerprinter,
	ctxLog Logger,
) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	return func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		ctxLog.Logf("Handshake callback")
		var hostname string
		if net.ParseIP(target.Hostname()) == nil {
			hostname = target.Hostname()
		}
		sni := info.ServerName
		remotePlaintextConn, err := h.dialer.Dial("tcp", target.Host)
		if err != nil {
			return nil, err
		}
		ctxLog.Logf("Remote conn established")
		needClose := true
		defer func() {
			if needClose {
				ctxLog.Logf("Closing remotePlaintextConn")
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

		if h.clientTLsCredentials != nil && remoteConfig.ServerName == h.clientTLsCredentials.Host {
			remoteConfig.ClientAuth = utls.RequireAndVerifyClientCert
			remoteConfig.GetClientCertificate = func(cri *utls.CertificateRequestInfo) (*utls.Certificate, error) {
				return &h.clientTLsCredentials.Cert, nil
			}
		}

		var fpRes *fpResult

		ctxLog.Logf("Wait for extractALPN")
		select {
		case err := <-chf.error():
			return nil, fmt.Errorf("error extracting ALPN: %v", err)
		case fpRes = <-chf.result():
			break
		}
		ctxLog.Logf("Done extractALPN")

		remoteConn := utls.UClient(remotePlaintextConn, remoteConfig, utls.HelloCustom)
		*remoteConnRes = remoteConn // Pass connection back
		spec := fpRes.helloSpec
		if spec == nil {
			return nil, fmt.Errorf("empty fingerprinted spec")
		}
		if err := remoteConn.ApplyPreset(spec); err != nil {
			return nil, err
		}
		if sni != "" {
			remoteConn.SetSNI(sni)
		}
		ctxLog.Logf("Remote handshake")

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

		ctxLog.Logf("Certificate generation")

		cert, err := generateCert(info, target.Hostname(), h.generateCertFunc)
		if err != nil {
			return nil, err
		}
		clientConfig.Certificates = []tls.Certificate{*cert}

		needClose = false
		return clientConfig, nil
	}
}

func generateCert(
	info *tls.ClientHelloInfo,
	target string,
	generateCertFunc func(ips []string, names []string) (*tls.Certificate, error),
) (*tls.Certificate, error) {
	sni := info.ServerName
	if sni != "" {
		return generateCertFunc(nil, []string{sni})
	}
	var ip, name []string
	if net.ParseIP(target) == nil {
		name = []string{target}
	} else {
		ip = []string{target}
	}
	return generateCertFunc(ip, name)
}

// clientHelloFingerprinter holds variables related to client TLS fingerprinting
type clientHelloFingerprinter struct {
	conn  io.Reader
	fpCh  chan *fpResult
	errCh chan error
	log   Logger
}

// fpResult is a container struct for client`s clientHello fingerprinting results
type fpResult struct {
	helloSpec  *utls.ClientHelloSpec
	nextProtos []string
}

func (f clientHelloFingerprinter) result() chan *fpResult {
	return f.fpCh
}

func (f clientHelloFingerprinter) error() chan error {
	return f.errCh
}

func (f clientHelloFingerprinter) extractALPN() {
	tlsHeader := make([]byte, 5)
	n, err := io.ReadAtLeast(f.conn, tlsHeader, 5)
	if err != nil {
		if err == io.EOF {
			f.errCh <- fmt.Errorf("TLS header: unexpected EOF at byte %d", n)
			return
		}
		f.errCh <- fmt.Errorf("TLS header: read error: %v", err)
		return
	}
	if tlsHeader[0] != 0x16 {
		f.errCh <- fmt.Errorf("TLS header: incorrect header: %v", tlsHeader)
		return
	}
	f.log.Logf("TLS header bytes: %v", tlsHeader)
	clientHelloLength := uint16(tlsHeader[3])<<8 + uint16(tlsHeader[4])
	f.log.Logf("ClientHello length: %d", clientHelloLength)
	clientHelloBody := make([]byte, clientHelloLength)
	n, err = io.ReadAtLeast(f.conn, clientHelloBody, int(clientHelloLength))
	if err != nil {
		if err == io.EOF {
			f.errCh <- fmt.Errorf("TLS body: unexpected EOF at byte %d", n)
			return
		}
		f.errCh <- fmt.Errorf("TLS body: read error: %v", err)
		return
	}
	clientHello := utls.UnmarshalClientHello(clientHelloBody)
	if clientHello == nil {
		f.errCh <- fmt.Errorf("failed to unmarshal clientHello")
		return
	}
	nextProtos := clientHello.AlpnProtocols
	f.log.Logf("Client ALPN offers: %v", nextProtos)

	fp := utls.Fingerprinter{
		KeepPSK:           false,
		AllowBluntMimicry: true,
		AlwaysAddPadding:  false,
	}
	clientHelloSpec, err := fp.FingerprintClientHello(append(tlsHeader, clientHelloBody...))
	if err != nil {
		f.log.Logf("Client hello fingerprinting error %v", err)
		f.errCh <- err
		return
	}
	f.log.Logf("Sending fpRes")
	f.fpCh <- &fpResult{
		helloSpec:  clientHelloSpec,
		nextProtos: nextProtos,
	}

	f.log.Logf("Start sinking ALPN copy")
	_, err = io.Copy(io.Discard, f.conn) // Sink remaining data - we don't need them
	if err != nil && !utils.IsClosedConnErr(err) {
		f.log.Warnf("Sinking failed, error: %v", err)
		f.errCh <- err
	}
}
