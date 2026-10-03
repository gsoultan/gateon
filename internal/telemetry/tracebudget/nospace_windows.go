// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build windows

package tracebudget

import (
	"errors"
	"syscall"
)

// The Windows codes for a full disk: ERROR_HANDLE_DISK_FULL and ERROR_DISK_FULL.
const (
	errorHandleDiskFull syscall.Errno = 39
	errorDiskFull       syscall.Errno = 112
)

// isNoSpace reports whether err is the filesystem saying it is full.
func isNoSpace(err error) bool {
	return errors.Is(err, errorDiskFull) || errors.Is(err, errorHandleDiskFull)
}
