TLS MITM proxy for reverse-engineering purposes
===

## Why

It is often necessary to decrypt TLS traffic when reverse-engineering applications.
This can easily be done with tools like [mitmproxy](https://github.com/mitmproxy/mitmproxy).
However, server can detect such MITM attack due to mitmproxy's a very specific TLS fingerprint 
(think [JA3](https://github.com/salesforce/ja3) and other implementations). OpenSSL backend
cannot be easily configured to mimic given fingerprint (if you know how to do it, please 
open issue and tell me). Servers can detect this and refuse connection or disallow access 
(for example, Cloudflare often does this).

## What

This tool is written to address these problems using awesome [utls](https://github.com/refraction-networking/utls)
library. For software under test (SUT) it looks like a usual HTTP proxy. When SUT connects through it, ClientHello
is fingerprinted and upstream connection with the same fingerprint is established. Data inside TLS tunnel are not
modified so higher-level fingerprints (like [HTTP/2 fingerprint from Akamai](https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf))
are also preserved. Both client and upstream connections` TLS keys are logged so tools like Wireshark can be used
to record and inspect traffic passively.

```
--------------           ---------------           --------------          --------------
|  Software  |           |   Mirror    |           |  Upstream  |          |   Remote   |
|   under    |<----+---->|   proxy     |<----+---->|   proxy    |<-------->|   Server   |
|   test     |     |     | (this tool) |     |     | (optional) |          |            |
--------------     |     ---------------     |     --------------          --------------
                   |           |             |
       +-----------+-----------)-------------+
       |                       |
       v                       v
--------------           ---------------
|  Sniffer   |           |   TLS key   |
| (Wireshark)|<----------|    log      |
|            |           |    file     |
--------------           ---------------
```

## How

This tool only logs encryption keys and does not record traffic. You need a sniffer. Wireshark has been tested, 
so instruction assumes it is used.

1. Generate and install root certificate for next step (`cert.pem` and `key.pem`)  
2. Start proxy (`./mirror_proxy -c cert.pem -k key.pem -s sslkeylogfile.log`)
3. [Configure TLS decryption](https://wiki.wireshark.org/TLS#using-the-pre-master-secret) in Wireshark using `sslkeylogfile.log`
4. Start traffic capture
5. Configure SUT to use proxy
6. Start SUT and begin looking at packets

Proxy can connect to target server through another proxy (`-p`, HTTP(S) and SOCKS5 are supported).
Additionally, you can disable decryption completely (`-m passthrough`) - all connection data will be forwarded
unaltered.

## What else

Installation:
```shell
go install github.com/fedosgad/mirror_proxy@latest
```

Manual build and run:
```shell
git clone https://github.com/fedosgad/mirror_proxy
cd mirror_proxy/
go build
```
then
```shell
./mirror_proxy -h
```
or (this automatically uses certificate and key from installed `mitmproxy`)
```shell
./mirror.sh -h
```

CLI usage:
```
$ ./mirror_proxy -h
Usage: cmd [FLAG]...

Flags:
    --verbose, -v           Turn on verbose logging                                   (type: bool; default: false)  
    --listen, -l            Address for proxy to listen on                            (type: string; default: :8080)
    --pprof                 Enable profiling server on http://{pprof}/debug/pprof/    (type: string)
    --mode, -m              Operation mode (available: mitm, passthrough)             (type: string; default: mitm) 
    --dial-timeout, -dt     Remote host dialing timeout                               (type: string; default: 5s)   
    --proxy, -p             Upstream proxy address (direct connection if empty)       (type: string)
    --proxy-timeout, -pt    Upstream proxy timeout                                    (type: string; default: 5s)   
    --certificate, -c       Path to root CA certificate                               (type: string)
    --key, -k               Path to root CA key                                       (type: string)
    --sslkeylog, -s         Path to SSL/TLS secrets log file                          (type: string; default: ssl.log)
    --insecure, -i          Allow connecting to insecure remote hosts                 (type: bool; default: false)
    -h, --help              show help                                                 (type: bool)
```