// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build !windows

package tracebudget

import (
	"errors"
	"syscall"
)

// isNoSpace reports whether err is the filesystem saying it is full. EDQUOT,
// a quota reached, is the same condition for this purpose.
func isNoSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT)
}
