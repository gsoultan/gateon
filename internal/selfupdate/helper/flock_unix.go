// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build unix

package helper

import (
	"os"
	"syscall"
)

// lockExclusive takes the helper's lock without waiting. The kernel drops
// it when the process exits, however it exits.
func lockExclusive(f *os.File) error {
	// #nosec G115 -- a file descriptor fits an int.
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}
