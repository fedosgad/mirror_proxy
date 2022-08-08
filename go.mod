module mirror_proxy

go 1.18

replace github.com/getlantern/utls v0.0.0-20211116192935-1abdc4b1acab => github.com/refraction-networking/utls v1.1.1

require (
	github.com/cosiner/flag v0.5.2
	github.com/elazarl/goproxy v0.0.0-20220529153421-8ea89ba92021
	github.com/getlantern/utls v0.0.0-20211116192935-1abdc4b1acab
	github.com/mwitkow/go-http-dialer v0.0.0-20161116154839-378f744fb2b8
	golang.org/x/net v0.0.0-20211111160137-58aab5ef257a
)

require (
	github.com/andybalholm/brotli v1.0.4 // indirect
	github.com/klauspost/compress v1.13.6 // indirect
	github.com/refraction-networking/utls v1.0.0 // indirect
	golang.org/x/crypto v0.0.0-20211108221036-ceb1ce70b4fa // indirect
	golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1 // indirect
)
