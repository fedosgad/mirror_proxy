package hijackers

import (
	"net"
	"net/url"
)

// Hijacker operation modes
const (
	ModePassthrough = "passthrough"
	ModeMITM        = "mitm"
)

// Hijacker is an entity of connection interceptor.
type Hijacker interface {
	// GetConns creates server connection and optionally wraps clientRaw into client.
	// Returned streams are meant to be connected to each other.
	// Implementation MUST answer to client "HTTP/1.1 200 OK\r\n\r\n"
	GetConns(url *url.URL, clientRaw net.Conn, ctxLogger Logger) (client, server net.Conn, err error)
}

type Logger interface {
	Logf(msg string, argv ...interface{})
	Warnf(msg string, argv ...interface{})
}

type Dialer interface {
	Dial(network string, addr string) (c net.Conn, err error)
}
