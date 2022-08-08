package hijackers

import (
	"crypto/tls"
	"io"

	"time"
)

type HijackerFactory struct {
	dialTimeout time.Duration

	allowInsecure    bool
	keyLogWriter     io.Writer
	generateCertFunc func(ips []string, names []string) (*tls.Certificate, error)
}

func NewHijackerFactory(
	dialTimeout time.Duration,
	allowInsecure bool,
	keyLogWriter io.Writer,
	generateCertFunc func(ips []string, names []string) (*tls.Certificate, error),
) *HijackerFactory {
	return &HijackerFactory{
		dialTimeout:      dialTimeout,
		allowInsecure:    allowInsecure,
		keyLogWriter:     keyLogWriter,
		generateCertFunc: generateCertFunc,
	}
}

func (hf *HijackerFactory) Get(mode string) Hijacker {
	switch mode {
	case ModePassthrough:
		return NewPassThroughHijacker(hf.dialTimeout)
	case ModeMITM:
		return NewUTLSHijacker(
			hf.allowInsecure,
			hf.keyLogWriter,
			hf.generateCertFunc,
			hf.dialTimeout,
		)
	default:
		return nil
	}
}
