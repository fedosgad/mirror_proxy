package utils

import (
	"bytes"
	"io"
)

// LimitedBuffer is a bytes.Buffer that will only hold first buf.Cap() bytes written to it.
// Everything else is discarded.
type LimitedBuffer struct {
	bytes.Buffer
	blackhole io.Writer
}

func NewLimitedBuffer() *LimitedBuffer {
	return &LimitedBuffer{
		Buffer:    bytes.Buffer{},
		blackhole: io.Discard,
	}
}

func (lb *LimitedBuffer) Write(p []byte) (n int, err error) {
	available := lb.Cap() - lb.Len()
	switch {
	case available == 0: // No room in buffer - discard
		return lb.blackhole.Write(p)
	case len(p) <= available: // Enough room in buffer - write everything there
		return lb.Buffer.Write(p)
	default: // Only part of p can fit into buffer - discard remains
		n, err := lb.Buffer.Write(p[:len(p)-available])
		if err != nil {
			return n, err
		}
		return lb.blackhole.Write(p)
	}
}
