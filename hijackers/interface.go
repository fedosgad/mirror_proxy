package hijackers

import (
	"net"
	"net/http"
)

// Hijacker is an entity of connection interceptor.
type Hijacker interface {
	// GetConns creates server connection and optionally wraps clientRaw into client.
	// Returned streams are meant to be connected to each other.
	// Implementation MUST answer to client "HTTP/1.1 200 Ok\r\n\r\n"
	GetConns(req *http.Request, clientRaw net.Conn) (client, server net.Conn, err error)
}
