package utils

import "net"

// Taken from github.com/syncthing/syncthing/lib/tlsutil/tlsutil.go

type UnionedConnection struct {
	first     [1]byte
	firstDone bool
	net.Conn
}

func (c *UnionedConnection) Read(b []byte) (n int, err error) {
	if !c.firstDone {
		if len(b) == 0 {
			// this probably doesn't happen, but handle it anyway
			return 0, nil
		}
		b[0] = c.first[0]
		c.firstDone = true
		return 1, nil
	}
	return c.Conn.Read(b)
}

// First returns one byte read from this connection. If no Read happened yet, second return value will be false.
func (c *UnionedConnection) First() (byte, bool) {
	if c.firstDone {
		return c.first[0], true
	}
	return 0, false
}
