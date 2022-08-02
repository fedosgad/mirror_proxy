package hijackers

import (
	"net"
	"net/url"
)

type passThroughHijacker struct{}

func NewPassThroughHijacker() Hijacker {
	return &passThroughHijacker{}
}

func (h *passThroughHijacker) GetConns(url *url.URL, clientConn net.Conn) (net.Conn, net.Conn, error) {
	d := net.Dialer{}
	remoteConn, err := d.Dial("tcp", url.Host)
	if err != nil {
		return nil, nil, err
	}
	//_, err = clientConn.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))
	return clientConn, remoteConn, err
}
