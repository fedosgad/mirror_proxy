package cert_generator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"time"
)

type CertificateGenerator struct {
	ca     tls.Certificate
	caX509 *x509.Certificate
}

func NewCertGenerator(ca tls.Certificate) (*CertificateGenerator, error) {
	caX509, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, err
	}
	return &CertificateGenerator{ca: ca, caX509: caX509}, nil
}

func NewCertGeneratorFromFiles(certFile, keyFile string) (*CertificateGenerator, error) {
	var certs []tls.Certificate
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("certificate and key files required")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	certs = []tls.Certificate{cert}
	return NewCertGenerator(certs[0])
}

func (cg *CertificateGenerator) GenChildCert(ips, names []string) (*tls.Certificate, error) {
	private, cab, err := cg.genCertBytes(ips, names)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{cab},
		PrivateKey:  private,
	}, nil
}

func (cg *CertificateGenerator) genCertBytes(ips []string, names []string) (*rsa.PrivateKey, []byte, error) {
	s, _ := rand.Prime(rand.Reader, 128)

	// Certificate validity period should be less than 13 month.
	// See https://stackoverflow.com/a/65239775
	// Thanks to Johnny Bravo for the tip!

	template := &x509.Certificate{
		SerialNumber:          s,
		Subject:               pkix.Name{Organization: []string{"mitmproxy"}},
		Issuer:                pkix.Name{Organization: []string{"mitmproxy"}},
		NotBefore:             time.Now().AddDate(0, 0, -7),
		NotAfter:              time.Now().AddDate(0, 0, 314),
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	if ips != nil {
		is := make([]net.IP, 0)
		for _, i := range ips {
			is = append(is, net.ParseIP(i))
		}
		template.IPAddresses = is
	}
	if names != nil {
		template.DNSNames = names
	}

	private := cg.ca.PrivateKey.(*rsa.PrivateKey)

	certP, _ := x509.ParseCertificate(cg.ca.Certificate[0])
	public := certP.PublicKey.(*rsa.PublicKey)

	cab, err := x509.CreateCertificate(rand.Reader, template, cg.caX509, public, private)
	if err != nil {
		return nil, nil, err
	}
	return private, cab, nil
}
