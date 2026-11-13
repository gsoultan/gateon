// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tls

import "testing"

// TestOffersPostQuantumKeyExchangeFollowsGODEBUG: the hybrid ML-KEM exchanges
// are Go's default, and tlsmlkem=0 is the one switch that turns them off --
// alone or among other settings, and nothing that merely resembles it.
func TestOffersPostQuantumKeyExchangeFollowsGODEBUG(t *testing.T) {
	for godebug, want := range map[string]bool{
		"":                          true,
		"http2client=0":             true,
		"tlsmlkem=1":                true,
		"tlsmlkem=0":                false,
		"http2client=0, tlsmlkem=0": false,
		"xtlsmlkem=0":               true,
	} {
		t.Setenv("GODEBUG", godebug)
		if got := OffersPostQuantumKeyExchange(); got != want {
			t.Errorf("GODEBUG=%q: OffersPostQuantumKeyExchange() = %v, want %v", godebug, got, want)
		}
	}
}
