package hijackers

import (
	"fmt"
	"io"
	"net"
)

type TeeConn struct {
	net.Conn
	pipeR  *io.PipeReader
	pipeW  *io.PipeWriter
	teeOut io.Reader
}

func NewTeeConn(conn net.Conn) (net.Conn, io.Reader) {
	pipeR, pipeW := io.Pipe()
	teeOut := io.TeeReader(conn, pipeW)
	return &TeeConn{
		Conn:   conn,
		pipeR:  pipeR,
		pipeW:  pipeW,
		teeOut: teeOut,
	}, teeOut
}

func (tc TeeConn) Read(p []byte) (n int, err error) {
	return tc.pipeR.Read(p)
}

func (tc TeeConn) Close() error {
	errConn := tc.Conn.Close()
	errPipeR := tc.pipeR.Close()
	errPipeW := tc.pipeW.Close()
	if errConn != nil || errPipeR != nil || errPipeW != nil {
		return fmt.Errorf("error(s) closing TeeConn: conn %v, pipeR %v, pipeW %v", errConn, errPipeR, errPipeW)
	}
	return nil
}

func (tc TeeConn) GetTeeReader() io.Reader {
	return tc.teeOut
}
