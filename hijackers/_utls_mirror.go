package hijackers

import (
	"fmt"
	utls "github.com/getlantern/utls"
	"io"
	"net"
	"net/http"
	"net/url"
	"tls_mirror/utls_factory"
)

type utlsMirrorHijacker struct {
	clientTLSConfig  *utls.Config
	generateCertFunc func(ips []string, names []string) (*utls.Certificate, error)
}

func NewUTLSMirrorHijacker(
	keyLogWriter io.Writer,
	genCertFunc func(ips []string, names []string) (*utls.Certificate, error),
) Hijacker {
	return &utlsMirrorHijacker{
		clientTLSConfig: &utls.Config{
			KeyLogWriter: keyLogWriter,
		},
		generateCertFunc: genCertFunc,
	}
}

// To get client's clientHello fingerprint (read - bytes), limited-length TeeReader is required
// Concept: read clientHello bytes, parse them with utls.FingerprintClientHello (need to handle unknown extensions),
// change fields where applicable and use resulting spec for an upstream TLS connection

func (h *utlsMirrorHijacker) GetConns(req *http.Request, clientConn net.Conn) (net.Conn, net.Conn, error) {
	errCh := make(chan error)
	done := make(chan struct{})
	clientConfig := h.clientTLSConfig.Clone()
	clientConfig.GetCertificate = h.clientHelloCallback(req.URL)
	plaintextConn := utls.Server(clientConn, clientConfig)
	_, err := clientConn.Write([]byte("HTTP/1.1 200 Ok\r\n\r\n"))
	if err != nil {
		return nil, nil, err
	}

	if err := plaintextConn.Handshake(); err != nil {
		return nil, nil, err
	}

	return plaintextConn, remoteConn, err
}

// clientHelloCallback performs the following tasks:
//
// - (?) fingerprint client connection
//
// - connect to and perform handshake with target server
//
// - generate certificate for client (according to client's SNI)
//
// - set correct ALPN for client connection
func (h *utlsMirrorHijacker) clientHelloCallback(target *url.URL, clientConn *utls.Conn) func(info *utls.ClientHelloInfo) (*utls.Certificate, error) {
	return func(info *utls.ClientHelloInfo) (*utls.Certificate, error) {
		remotePlaintextConn, err := net.Dial("tcp", target.Host)
		if err != nil {
			remotePlaintextConn.Close()
			return nil, err
		}
		utls.

		remoteConn := utls.UClient(remotePlaintextConn, remoteConfig, utls.HelloCustom)
		spec := utls_factory.GetConnSpec(h.connSpecName)
		if spec == nil {
			return nil, nil, fmt.Errorf("invalid connection spec name %s", h.connSpecName)
		}
		if err := remoteConn.ApplyPreset(spec); err != nil {
			return nil, nil, err
		}
		if sni != "" {
			remoteConn.SetSNI(sni)
		}
		err = remoteConn.Handshake()

		return generateCertUTLS(info, target.Hostname(), h.generateCertFunc)
	}
}
