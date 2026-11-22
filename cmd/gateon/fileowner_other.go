// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build !unix

package main

// fileOwner reports nothing where files have no unix owner.
func fileOwner(string) (uid, gid int, ok bool) { return 0, 0, false }

// chownIfPresent does nothing where files have no unix owner.
func chownIfPresent(string, int, int) error { return nil }
