package hijackers

import utls "github.com/refraction-networking/utls"

type ClientTLsCredentials struct {
	Host string
	Cert utls.Certificate
}
