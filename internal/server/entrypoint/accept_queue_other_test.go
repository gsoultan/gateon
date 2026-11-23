// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build !linux

package entrypoint

import (
	"net"
	"testing"
)

// waitForAccept cannot see the accept queue off Linux, so the shutdown tests
// there keep the race the Linux version closes.
func waitForAccept(_ *testing.T, _ net.Addr) {}
