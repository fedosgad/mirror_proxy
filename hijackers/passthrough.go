package hijackers

import (
	"net"
	"net/url"
	"time"
)

type passThroughHijacker struct {
	dialTimeout time.Duration
}

func NewPassThroughHijacker(dialTimeout time.Duration) Hijacker {
	return &passThroughHijacker{
		dialTimeout: dialTimeout,
	}
}

func (h *passThroughHijacker) GetConns(url *url.URL, clientRaw net.Conn) (net.Conn, net.Conn, error) {
	d := net.Dialer{
		Timeout: h.dialTimeout,
	}
	remoteConn, err := d.Dial("tcp", url.Host)
	if err != nil {
		return nil, nil, err
	}
	_, err = clientRaw.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))
	return clientRaw, remoteConn, err
}
