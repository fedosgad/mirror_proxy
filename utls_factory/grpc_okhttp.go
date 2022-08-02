package utls_factory

import tls "github.com/getlantern/utls"

const GrpcOkhttpConn = "grpc_okhttp"

func init() {
	connProfiles[GrpcOkhttpConn] = grpcOkhttpConfig{}
}

type grpcOkhttpConfig struct{}

// grpc-java-okhttp/1.45.1
func (grpcOkhttpConfig) getSpec() *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		CompressionMethods: []byte{
			0x00, // compressionNone
		},
		Extensions: []tls.TLSExtension{
			&tls.RenegotiationInfoExtension{},
			&tls.SNIExtension{},
			&tls.UtlsExtendedMasterSecretExtension{},
			&tls.SessionTicketExtension{},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
				tls.PKCS1WithSHA1,
			}},
			&tls.StatusRequestExtension{},
			&tls.ALPNExtension{AlpnProtocols: []string{"h2"}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{
				0x00, // pointFormatUncompressed
			}},
			&tls.SupportedCurvesExtension{[]tls.CurveID{
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			}},
		},
	}
}
