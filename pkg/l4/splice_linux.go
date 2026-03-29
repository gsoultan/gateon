//go:build linux

package l4

import (
	"net"
	"syscall"
)

// SpliceCopy attempts to zero-copy data from src to dst using splice(2).
// Both must be *net.TCPConn for optimal performance.
func SpliceCopy(dst, src net.Conn) (int64, error) {
	dstTCP, ok1 := dst.(*net.TCPConn)
	srcTCP, ok2 := src.(*net.TCPConn)
	if !ok1 || !ok2 {
		return 0, syscall.ENOSYS
	}

	dstFile, err := dstTCP.File()
	if err != nil {
		return 0, err
	}
	defer dstFile.Close()

	srcFile, err := srcTCP.File()
	if err != nil {
		return 0, err
	}
	defer srcFile.Close()

	var total int64
	for {
		n, err := syscall.Splice(int(srcFile.Fd()), nil, int(dstFile.Fd()), nil, 1024*1024, 0)
		if n > 0 {
			total += n
		}
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EINTR {
				continue
			}
			return total, err
		}
		if n == 0 {
			break
		}
	}
	return total, nil
}
