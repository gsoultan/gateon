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

// TestWithStateAcceptsNil covers the path a middleware takes when it forwards
// a request it did not resolve state for.
//
// What it does NOT claim is that the reader reports absence. WithState stores
// whatever it is handed, so a nil goes into the context as a non-nil `any`
// carrying a typed nil, and GetRequestStateFromContext returns it verbatim.
// Callers see a nil *RequestState either way and the existing `rs != nil`
// guards hold, which is why this is documented rather than fixed -- but an
// earlier version of this test asserted the opposite and could not tell the
// difference, because a typed nil compares equal to nil at that return type.
//
// The assertion here is the one that is actually load-bearing: no panic, and
// callers can still use their nil check.
func TestWithStateAcceptsNil(t *testing.T) {
	ctx := WithState(context.Background(), nil)

	if got := GetRequestStateFromContext(ctx); got != nil {
		t.Errorf("round-tripping nil produced %+v, want a nil *RequestState", got)
	}

	// The stored value is a non-nil interface holding a typed nil. Pinned so
	// that anyone who later adds a `ctx.Value(...) != nil` check knows it
	// always passes and is not the absence test it looks like.
	if v := ctx.Value(RequestStateContextKey{}); v == nil {
		t.Error("the stored value is now an untyped nil; that is an " +
			"improvement, but the comment above and any caller relying on " +
			"the documented behaviour need updating with it")
	}
}
