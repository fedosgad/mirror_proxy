// Package utls_factory implements creation of TLS connections with desired fingerprints.
//
// Features managed by this package:
// 	1. Proxy handling. Given proxy of any type (HTTP(S)/SOCKS) is used to dial target server.
// 	2. TLS settings manipulation. A complete TLS connection profile can be set for a connection
//	(ex.: to counter JA3 (https://github.com/salesforce/ja3) or similar fingerprinting).
// 	3. SSL/TLS key logging. If needed for debug purposes (ex.: to use Wireshark`s TLS decryption),
//		encryption keys can be logged to a file.
//
// Whole profile is contained in a single file (ex.: chrome_conn.go).
// All connection profiles are registered in a global map to simplify adding new profiles.
package utls_factory
