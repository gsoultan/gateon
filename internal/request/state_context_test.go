// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package request

import (
	"context"
	"testing"
)

// WithState and GetRequestStateFromContext are the writer and reader for the
// one context value the whole middleware chain depends on: EntryPoint resolves
// the client IP, country, request ID and fingerprints once and stores them
// here, and every middleware downstream reads them back instead of
// recomputing. A round trip that silently returns nil turns every one of those
// reads into a zero value, and several of them are what security decisions are
// keyed on.

func TestStateRoundTripsThroughContext(t *testing.T) {
	rs := &RequestState{RouteName: "api", ClientRemoteAddr: "203.0.113.4", RequestID: "abc"}

	got := GetRequestStateFromContext(WithState(context.Background(), rs))
	if got == nil {
		t.Fatal("GetRequestStateFromContext returned nil for a context WithState " +
			"had just written; every downstream read would see a zero value")
	}
	if got != rs {
		t.Errorf("got %p, want the same pointer %p: the chain mutates this state "+
			"in place, so a copy would drop everything written after EntryPoint", got, rs)
	}
}

// TestStateIsAbsentRatherThanZeroWhenUnset pins the other half. Callers test
// the result against nil to decide whether the chain ran; returning a zero
// RequestState instead would read as "resolved, and the client has no address".
func TestStateIsAbsentRatherThanZeroWhenUnset(t *testing.T) {
	if got := GetRequestStateFromContext(context.Background()); got != nil {
		t.Errorf("GetRequestStateFromContext on a bare context = %+v, want nil", got)
	}
}

// TestWithStateAcceptsNil covers the path a middleware takes when it forwards a
// request it did not resolve state for. It must not panic, and the reader must
// still report absence rather than handing back a typed nil that callers then
// dereference.
func TestWithStateAcceptsNil(t *testing.T) {
	if got := GetRequestStateFromContext(WithState(context.Background(), nil)); got != nil {
		t.Errorf("round-tripping nil produced %+v, want nil", got)
	}
}
