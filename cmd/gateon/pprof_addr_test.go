// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"testing"
)

// TestPprofRefusesAnAddressOffLoopback: the profiling server has no
// authentication, and GATEON_PPROF_ADDR=:6060 served it on every interface.
// Root cause: the address was passed to the listener unchecked, so "loopback
// only" was advice in a comment rather than a property of the server.
func TestPprofRefusesAnAddressOffLoopback(t *testing.T) {
	for _, tc := range []struct {
		addr        string
		allowRemote bool
		refused     bool
	}{
		{addr: "127.0.0.1:6060"},
		{addr: "[::1]:6060"},
		{addr: "localhost:6060"},
		{addr: ":6060", refused: true},
		{addr: "0.0.0.0:6060", refused: true},
		{addr: "[::]:6060", refused: true},
		{addr: "10.0.0.5:6060", refused: true},
		{addr: "0.0.0.0:6060", allowRemote: true},
	} {
		err := checkPprofAddr(tc.addr, tc.allowRemote)
		if refused := errors.Is(err, errPprofNotLoopback); refused != tc.refused {
			t.Errorf("checkPprofAddr(%q, allowRemote=%v) = %v, want refused=%v", tc.addr, tc.allowRemote, err, tc.refused)
		}
	}
	if err := checkPprofAddr("6060", false); err == nil {
		t.Error("an address with no port was accepted")
	}
}
