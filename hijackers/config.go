package hijackers

import utls "github.com/refraction-networking/utls"

type ClientTLSCredentials struct {
	Host string
	Cert utls.Certificate
}
