package utils

import "net"

func IsClosedConnErr(err error) bool {
	netOpError, ok := err.(*net.OpError)
	return ok && netOpError.Err.Error() == "use of closed network connection"
}
