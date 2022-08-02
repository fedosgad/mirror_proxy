package hijackers

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
)

type stdlibHijacker struct {
	clientTLSConfig    *tls.Config
	remoteTLSConfig    *tls.Config
	certGenConstructor func(ips, names []string) func(info *tls.ClientHelloInfo) (*tls.Certificate, error)
}

func NewStdlibHijacker(
	keyLogWriter io.Writer,
	certGenConstructor func(ips []string, names []string) func(info *tls.ClientHelloInfo) (*tls.Certificate, error),
) Hijacker {
	return &stdlibHijacker{
		clientTLSConfig: &tls.Config{
			KeyLogWriter: keyLogWriter,
		},
		remoteTLSConfig: &tls.Config{
			KeyLogWriter: keyLogWriter,
		},
		certGenConstructor: certGenConstructor,
	}
}

func (h *stdlibHijacker) GetConns(req *http.Request, clientConn net.Conn) (net.Conn, net.Conn, error) {
	var ips, names []string
	target := []string{req.URL.Hostname()}
	if net.ParseIP(target[0]) == nil {
		names = target
	} else {
		ips = target
	}
	config := h.clientTLSConfig.Clone()
	config.GetCertificate = h.certGenConstructor(ips, names)
	plaintextConn := tls.Server(clientConn, config)

	remoteConn, err := tls.Dial("tcp", req.URL.Host, h.remoteTLSConfig.Clone())
	if err != nil {
		return nil, nil, err
	}
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Ok\r\n\r\n"))
	return plaintextConn, remoteConn, err
}
