// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package phantom

import (
	"net"
	"testing"
)

func TestPhantomCore_Optimize(t *testing.T) {
	core := NewPhantomCore(nil)
	defer core.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer l.Close()

	opt := core.OptimizeListener(l)
	if opt == nil {
		t.Error("Expected listener, got nil")
	}
}

func TestPhantomCore_Status(t *testing.T) {
	core := NewPhantomCore(nil)
	_, engine, _ := core.GetStatus()

	// On macOS, enabled should be false (no io_uring/AF_XDP)
	// but it should still return a valid engine string.
	if engine == "" {
		t.Error("Empty engine string returned")
	}

	core.Close()
}
