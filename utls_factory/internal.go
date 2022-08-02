package utls_factory

import (
	tls "github.com/getlantern/utls"
)

type tlsHandshakeTimeoutError struct{}

func (tlsHandshakeTimeoutError) Timeout() bool   { return true }
func (tlsHandshakeTimeoutError) Temporary() bool { return true }
func (tlsHandshakeTimeoutError) Error() string   { return "net/http: TLS handshake timeout" }

type connConfig interface {
	getSpec() *tls.ClientHelloSpec
}
