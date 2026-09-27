// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package l4

import (
	"net"
	"syscall"
)

// spliceSupported is true: between two *net.TCPConn, SpliceCopy reaches
// splice(2) through the standard library.
const spliceSupported = true

// SpliceCopy copies src to dst with splice(2), through (*net.TCPConn).ReadFrom.
// It refuses (ENOSYS) unless both ends are *net.TCPConn: ReadFrom from any
// other source copies anyway, through a 32 KiB buffer it allocates for the
// call, which is the copy the caller's pooled fallback exists to replace.
func SpliceCopy(dst, src net.Conn) (int64, error) {
	dstTCP, ok1 := dst.(*net.TCPConn)
	_, ok2 := src.(*net.TCPConn)
	if !ok1 || !ok2 {
		return 0, syscall.ENOSYS
	}
	return dstTCP.ReadFrom(src)
}
