// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package logger

import (
	"sync"
	"testing"
)

// TestReconfigureIsSafeWhileLogging reproduces a race that main.go performs on
// every boot with pprof enabled.
//
// cmd/gateon calls logger.Init early, starts the pprof server -- whose goroutine
// logs immediately -- and only then calls logger.InitWithConfig once the config
// file has been read. initInternal reassigned the package-level L pointer, so
// that second call is an unsynchronised write racing every reader in the
// process. Nothing exercised it, so -race never saw it.
//
// Under -race this fails against a pointer-swapping implementation and passes
// once the swap happens inside the shim.
func TestReconfigureIsSafeWhileLogging(t *testing.T) {
	const (
		readers = 8
		rounds  = 200
	)

	var wg sync.WaitGroup

	// Each reader does a fixed number of iterations rather than looping until
	// a stop channel closes. Under "until stopped", how many times these lines
	// run is a scheduling outcome: at GOMAXPROCS=1 the readers never ran at all
	// before the writer finished and closed the channel, which took this
	// package's measured coverage from 38.8% to 28.2% and failed the coverage
	// ratchet on an unrelated pull request. A bounded count executes the same
	// statements on every host, and still interleaves with the writer below --
	// which is the thing being tested, and which the race detector is what
	// actually judges.
	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range rounds {
				// Both styles, because both are used across the codebase.
				L.LogInfo("serving", "path", "/healthz")
				L.Info().Str("path", "/healthz").Msg("serving")
			}
		}()
	}

	for range rounds {
		if err := Init(true); err != nil {
			t.Fatalf("Init: %v", err)
		}
		if err := InitWithConfig("debug", false); err != nil {
			t.Fatalf("InitWithConfig: %v", err)
		}
	}

	wg.Wait()
}

// TestDefaultNeverReturnsNil guards the accessor the whole package leans on: a
// nil inner logger would panic on the first call, in a process that has already
// started serving.
func TestDefaultNeverReturnsNil(t *testing.T) {
	if got := Default(); got == nil {
		t.Fatal("Default() returned nil")
	}
	// Must not panic even before Init has ever run.
	Default().LogInfo("hello")
}
