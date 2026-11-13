// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build !unix

package sockets

import "syscall"

// Inherit returns a store that keeps nothing: there is no service manager
// here to hold a socket.
func Inherit() *Store {
	return &Store{kept: make(map[string]bool)}
}

// notifier is never built on this platform.
type notifier struct{}

func (*notifier) store(string, syscall.Conn) error { return nil }
func (*notifier) remove(string) error              { return nil }
