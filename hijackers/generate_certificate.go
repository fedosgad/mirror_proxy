package hijackers

import (
	"crypto/tls"
	utls "github.com/getlantern/utls"
	"net"
)

func generateCert(
	info *tls.ClientHelloInfo,
	target string,
	generateCertFunc func(ips []string, names []string) (*tls.Certificate, error),
) (*tls.Certificate, error) {
	sni := info.ServerName
	if sni != "" {
		return generateCertFunc(nil, []string{sni})
	}
	var ip, name []string
	if net.ParseIP(target) == nil {
		name = []string{target}
	} else {
		ip = []string{target}
	}
	return generateCertFunc(ip, name)
}

func generateCertUTLS(
	info *utls.ClientHelloInfo,
	target string,
	generateCertFunc func(ips []string, names []string) (*utls.Certificate, error),
) (*utls.Certificate, error) {
	sni := info.ServerName
	if sni != "" {
		return generateCertFunc(nil, []string{sni})
	}
	var ip, name []string
	if net.ParseIP(target) == nil {
		name = []string{target}
	} else {
		ip = []string{target}
	}
	return generateCertFunc(ip, name)
}
