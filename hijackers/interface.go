package hijackers

import (
	"net"
	"net/url"
)

type Logger interface {
	Logf(msg string, argv ...interface{})
	Warnf(msg string, argv ...interface{})
}

// StatusReporter is a callback function that informs client on upstream connection status.
// Intended use - writing "200 OK"/"50x error" to client
type StatusReporter func(successful bool)

// Hijacker is an entity of connection interceptor.
type Hijacker interface {
	// GetConns creates server connection and optionally wraps clientRaw into client.
	// Returned streams are meant to be connected to each other.
	// Implementation MUST answer to client "HTTP/1.1 200 Ok\r\n\r\n"
	GetConns(url *url.URL, clientRaw net.Conn) (client, server net.Conn, err error)
}
