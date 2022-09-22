#!/bin/sh
go run . -c ~/.mitmproxy/mitmproxy-ca-cert.pem -k ~/.mitmproxy/mitmproxy-ca.pem "$@"
