package hijackers

import (
	"net"
	"net/http"
)

type passThroughHijacker struct{}

func NewPassThroughHijacker() Hijacker {
	return &passThroughHijacker{}
}

func (h *passThroughHijacker) GetConns(req *http.Request, clientConn net.Conn) (net.Conn, net.Conn, error) {
	d := net.Dialer{}
	remoteConn, err := d.Dial("tcp", req.URL.Host)
	if err != nil {
		return nil, nil, err
	}
	//_, err = clientConn.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))
	return clientConn, remoteConn, err
}
