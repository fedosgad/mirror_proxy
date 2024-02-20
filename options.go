package main

import (
	"log"
	"time"

	"github.com/cosiner/flag"
)

type Options struct {
	Verbose       bool   `names:"--verbose, -v" usage:"Turn on verbose logging" default:"false"`
	ListenAddress string `names:"--listen, -l" usage:"Address for proxy to listen on" default:":8080"`
	PprofAddress  string `names:"--pprof" usage:"Enable profiling server on http://{pprof}/debug/pprof/" default:""`

	Mode string `names:"--mode, -m" usage:"Operation mode (available: mitm, passthrough)" default:"mitm"`

	DialTimeout       time.Duration `names:"-"`
	DialTimeoutArg    string        `names:"--dial-timeout, -dt" usage:"Remote host dialing timeout" default:"5s"`
	ProxyAddr         string        `names:"--proxy, -p" usage:"Upstream proxy address (direct connection if empty)" default:""`
	ProxyTimeout      time.Duration `names:"-"`
	ProxyTimeoutArg   string        `names:"--proxy-timeout, -pt" usage:"Upstream proxy timeout" default:"5s"`
	HostWithMutualTLS string        `names:"--mutual-tls-host, -mth" usage:"Host where mutual TLS is enabled"`
	ClientCertFile    string        `names:"--client-cert, -cc" usage:"Path to file with client certificate"`
	ClientKeyFile     string        `names:"--client-key, -ck" usage:"Path to file with client key"`
	CertFile          string        `names:"--certificate, -c" usage:"Path to root CA certificate" default:""`
	KeyFile           string        `names:"--key, -k" usage:"Path to root CA key" default:""`
	SSLLogFile        string        `names:"--sslkeylog, -s" usage:"Path to SSL/TLS secrets log file" default:"ssl.log"`
	AllowInsecure     bool          `names:"--insecure, -i" usage:"Allow connecting to insecure remote hosts" default:"false"`
}

func getOptions() *Options {
	opts := &Options{}
	err := flag.Commandline.ParseStruct(opts)
	if err != nil {
		log.Fatal(err)
	}
	parseDuration(opts.DialTimeoutArg, &opts.DialTimeout)
	parseDuration(opts.ProxyTimeoutArg, &opts.ProxyTimeout)
	opts.check()
	return opts
}

func (o Options) check() {
	failIfEmpty := func(val, err string) {
		if val == "" {
			log.Fatal(err)
		}
	}

	failIfEmpty(o.ListenAddress, "Please provide listen address")
	if o.Mode != "mitm" && o.Mode != "passthrough" {
		log.Fatal()
	}
	if o.Mode != "mitm" {
		return
	}
	// TLS-related options
	failIfEmpty(o.CertFile, "Please provide certificate file")
	failIfEmpty(o.KeyFile, "Please provide key file")
	failIfEmpty(o.SSLLogFile, "Please provide key log file")

	if o.DialTimeout == 0 {
		log.Println("Warning: timeout=0, connections may hang!")
	}

	// mutual TLS related options
	if o.HostWithMutualTLS != "" {
		failIfEmpty(o.ClientCertFile, "Please provide client certificate file")
		failIfEmpty(o.ClientKeyFile, "Please provide client key file")
	}
}

func parseDuration(inp string, res *time.Duration) {
	d, err := time.ParseDuration(inp)
	if err != nil {
		log.Fatal(err)
	}
	*res = d
}
