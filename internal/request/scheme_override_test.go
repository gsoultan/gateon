// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package request

import (
	"net/http/httptest"
	"testing"
)

// TestForcedSchemeBeatsTheProxysHeader: the forwardedheaders middleware
// exists for a route behind a load balancer that reports the wrong scheme --
// it terminates TLS and says http. RealIP had already recorded that trusted
// proxy's X-Forwarded-Proto in the request state, and Scheme read the state
// first, so the operator's forced https lost to the very header it was set to
// correct: redirects, cookies' Secure flag and X-Forwarded-Proto upstream all
// said http. Scheme's own documentation puts the override first.
func TestForcedSchemeBeatsTheProxysHeader(t *testing.T) {
	r := httptest.NewRequest("GET", "http://app.example.com/", nil)
	rs := &RequestState{ForwardedProto: "http"} // what RealIP records from the LB
	ctx := WithForwardedProto(WithState(r.Context(), rs), "https")
	if got := Scheme(r.WithContext(ctx)); got != "https" {
		t.Fatalf("Scheme = %q with a forced https behind a proxy reporting http, want https", got)
	}

	// Without an override, the trusted proxy's scheme still stands.
	if got := Scheme(r.WithContext(WithState(r.Context(), rs))); got != "http" {
		t.Fatalf("Scheme without an override = %q, want the proxy's http", got)
	}
}
