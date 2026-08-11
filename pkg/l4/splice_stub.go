// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build !linux

package l4

import (
	"errors"
	"net"
)

var errSpliceNotSupported = errors.New("splice not supported on this platform")

// SpliceCopy is a stub for non-Linux platforms.
func SpliceCopy(dst, src net.Conn) (int64, error) {
	return 0, errSpliceNotSupported
}
