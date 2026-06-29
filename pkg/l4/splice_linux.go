//go:build linux

package l4

import (
	"net"
	"syscall"
)

// SpliceCopy attempts to zero-copy data from src to dst using splice(2).
// On Linux, this is achieved by leveraging Go's built-in support in (*net.TCPConn).ReadFrom.
func SpliceCopy(dst, src net.Conn) (int64, error) {
	dstTCP, ok1 := dst.(*net.TCPConn)
	if !ok1 {
		return 0, syscall.ENOSYS
	}
	return dstTCP.ReadFrom(src)
}
