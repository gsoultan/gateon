// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package phantom

import (
	"sync"
	"testing"
)

// shared holds the one io_uring core the tests in this package use unless they
// need to close a core themselves.
//
// It is shared because a ring is never given back: go-uring's Ring.Close
// unmaps the submission and completion rings but not the SQE array, so the
// mapping keeps the whole io_uring instance -- and its charge against locked
// memory -- alive until the process exits. Four create-and-close cycles
// exhaust the default 8 MiB RLIMIT_MEMLOCK, after which newPhantomCore falls
// back to standard I/O without a word, and every io_uring test after that
// would pass against the fallback instead of the ring.
var shared struct {
	once sync.Once
	core *linuxCore
}

// uringCore returns a core with a live ring, built the way cmd/gateon builds
// it: GATEON_PHANTOM=1 and an eBPF manager that is never nil.
func uringCore(t *testing.T) *linuxCore {
	t.Helper()
	shared.once.Do(func() { shared.core = newUringCore(t) })
	if shared.core == nil {
		t.Skip("io_uring is unavailable here (seccomp, SELinux, io_uring_disabled " +
			"or locked memory): these tests prove nothing about the ring on this host")
	}
	return shared.core
}

// newUringCore builds a core of the caller's own, for a test that closes it.
// It returns nil when the kernel refuses a ring.
func newUringCore(t *testing.T) *linuxCore {
	t.Helper()
	t.Setenv("GATEON_PHANTOM", "1")
	c, ok := newPhantomCore(holderLike{}).(*linuxCore)
	if !ok || c.ring == nil {
		return nil
	}
	return c
}

// TestStatusNamesIOURingWhileItsRingIsUp is the other half of
// TestStatusClaimsNoAccelerationThatIsNotRunning: with a ring up, the engine
// is io_uring and nothing more. It read "io_uring + AF_XDP" here, because the
// eBPF manager that is always present was taken as evidence of AF_XDP.
func TestStatusNamesIOURingWhileItsRingIsUp(t *testing.T) {
	core := uringCore(t)
	enabled, engine, _ := core.GetStatus()
	if !enabled || engine != "io_uring" {
		t.Errorf("GetStatus with a live ring = (%v, %q), want (true, \"io_uring\")",
			enabled, engine)
	}
}
