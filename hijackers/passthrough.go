package hijackers

import (
	"net"
	"net/url"
)

type passThroughHijacker struct {
	dialer Dialer
}

func NewPassThroughHijacker(dialer Dialer) Hijacker {
	return &passThroughHijacker{
		dialer: dialer,
	}
}

func (h *passThroughHijacker) GetConns(url *url.URL, clientRaw net.Conn, _ Logger) (net.Conn, net.Conn, error) {
	remoteConn, err := h.dialer.Dial("tcp", url.Host)
	if err != nil {
		return nil, nil, err
	}
	_, err = clientRaw.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
	return clientRaw, remoteConn, err
}
