// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build unix

package main

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// fileOwner is who owns path, so a file root writes can be handed back to
// them; ok is false when path does not exist or says nothing.
func fileOwner(path string) (uid, gid int, ok bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, 0, false
	}
	st, isUnix := fi.Sys().(*syscall.Stat_t)
	if !isUnix {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}

// chownIfPresent gives path to uid and gid, if it exists.
func chownIfPresent(path string, uid, gid int) error {
	if err := os.Lchown(path, uid, gid); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
