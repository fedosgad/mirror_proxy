package utls_factory

import (
	utls "github.com/getlantern/utls"
)

func init() {
	utls.EnableWeakCiphers()
}

var connProfiles = make(map[string]connConfig)

// GetConnSpec returns ClientHelloSpec with corresponding name
func GetConnSpec(name string) *utls.ClientHelloSpec {
	connProf, ok := connProfiles[name]
	if !ok {
		return nil
	}
	return connProf.getSpec()
}

// GetConnSpecWithALPN returns ClientHelloSpec with corresponding name.
// If spec includes ALPN extension, it`s default protocols are replaced with nextProtos.
// Otherwise, this function is identical to GetConnSpec
func GetConnSpecWithALPN(name string, nextProtos []string) *utls.ClientHelloSpec {
	connProf, ok := connProfiles[name]
	if !ok {
		return nil
	}
	spec := connProf.getSpec()
	for _, extension := range spec.Extensions {
		if alpnExt, ok := extension.(*utls.ALPNExtension); ok {
			alpnExt.AlpnProtocols = nextProtos
			break
		}
	}
	return spec
}
