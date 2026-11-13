// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"testing"

	"github.com/gsoultan/gateon/internal/resource"
)

func flags() SystemMetrics {
	var sm SystemMetrics
	setFeatureFlags(&sm)
	return sm
}

// TestSnapshotReportsPostQuantumKeyExchangeAsTLSDoes: the live snapshot said
// pqcEnabled true unconditionally, under a comment claiming ML-DSA as well.
// The Diagnostics API was corrected to follow GODEBUG=tlsmlkem=0 and this
// field was left behind, so the same gateway answered the same question two
// ways.
func TestSnapshotReportsPostQuantumKeyExchangeAsTLSDoes(t *testing.T) {
	t.Setenv("GODEBUG", "")
	if !flags().PqcEnabled {
		t.Error("with Go's default key exchanges, the snapshot reports post-quantum key exchange off")
	}
	t.Setenv("GODEBUG", "tlsmlkem=0")
	if flags().PqcEnabled {
		t.Error("with GODEBUG=tlsmlkem=0, the snapshot still reports post-quantum key exchange on")
	}
}

// TestSnapshotGovernorIsEnabledOnlyWhileItRuns: resourceGovernorEnabled was
// true for any governor registered, whether or not its loop had started.
func TestSnapshotGovernorIsEnabledOnlyWhileItRuns(t *testing.T) {
	prev := globalGovernor.Load()
	t.Cleanup(func() {
		if prev != nil {
			globalGovernor.Store(prev)
		} else {
			globalGovernor.Store(&governorProviderContainer{})
		}
	})
	SetGovernorProvider(resource.NewGovernor())
	if flags().ResourceGovernorEnabled {
		t.Error("a governor that was never started is reported as enabled")
	}
}
