// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// EvaluateCORS is what the dashboard's CORS tester calls to tell an operator
// whether a given origin would be allowed, and why not when it would not. It
// had no test, which matters twice over: an operator who is told an origin is
// refused when it is actually allowed will widen a policy that did not need
// widening, and one told the opposite will believe a boundary exists where it
// does not.

func preflight(origin, method, headers string) *http.Request {
	r := httptest.NewRequest(http.MethodOptions, "http://gw.example/api", nil)
	r.Header.Set("Origin", origin)
	r.Header.Set("Access-Control-Request-Method", method)
	if headers != "" {
		r.Header.Set("Access-Control-Request-Headers", headers)
	}
	return r
}

func TestEvaluateCORSAllowsAConfiguredOrigin(t *testing.T) {
	cfg := map[string]string{
		"allowed_origins": "https://app.example",
		"allowed_methods": "GET,POST",
	}

	d := EvaluateCORS(cfg, preflight("https://app.example", http.MethodPost, ""))
	if !d.IsPreflight {
		t.Error("IsPreflight = false for an OPTIONS carrying Origin and " +
			"Access-Control-Request-Method")
	}
	if !d.OriginAllowed || !d.Allowed {
		t.Errorf("OriginAllowed=%v Allowed=%v, want both true for a configured origin",
			d.OriginAllowed, d.Allowed)
	}
}

func TestEvaluateCORSRefusesAnUnconfiguredOrigin(t *testing.T) {
	cfg := map[string]string{"allowed_origins": "https://app.example"}

	d := EvaluateCORS(cfg, preflight("https://evil.example", http.MethodGet, ""))
	if d.OriginAllowed || d.Allowed {
		t.Errorf("OriginAllowed=%v Allowed=%v for an origin that is not in the "+
			"allow list; the dashboard would report a boundary that does not hold",
			d.OriginAllowed, d.Allowed)
	}
}

// TestEvaluateCORSSeparatesAMethodFromAHeader is the distinction the extra
// probe inside EvaluateCORS exists to make. rs/cors answers yes or no, so
// without it an operator refused for asking a disallowed *header* would be
// told the *method* was the problem and go and widen the method list, which
// does nothing and leaves the policy broader than it was.
func TestEvaluateCORSSeparatesAMethodFromAHeader(t *testing.T) {
	cfg := map[string]string{
		"allowed_origins": "https://app.example",
		"allowed_methods": "GET",
		"allowed_headers": "Content-Type",
	}

	t.Run("disallowed method", func(t *testing.T) {
		d := EvaluateCORS(cfg, preflight("https://app.example", http.MethodDelete, ""))
		if d.Allowed {
			t.Fatal("DELETE was allowed against a GET-only policy")
		}
		if d.MethodAllowed {
			t.Error("MethodAllowed = true for DELETE against a GET-only policy")
		}
	})

	t.Run("allowed method, disallowed header", func(t *testing.T) {
		d := EvaluateCORS(cfg, preflight("https://app.example", http.MethodGet, "X-Custom"))
		if d.Allowed {
			t.Fatal("a request for a header outside the policy was allowed")
		}
		if !d.MethodAllowed {
			t.Error("MethodAllowed = false, but GET is in the policy: the " +
				"operator would be sent to widen the method list, which changes " +
				"nothing and leaves the header still refused")
		}
		if d.HeadersAllowed {
			t.Error("HeadersAllowed = true for a header outside the policy")
		}
	})
}

// TestCORSEffectivePolicyReportsWhatIsEnforced covers the display path. An
// empty list in config is not "nothing allowed" -- rs/cors substitutes a
// default -- so reporting the raw config would show an operator a policy far
// narrower than the one actually in force.
func TestCORSEffectivePolicyReportsWhatIsEnforced(t *testing.T) {
	got := corsEffectivePolicy(CORSConfig{})

	if len(got.AllowedOrigins) != 1 || got.AllowedOrigins[0] != "*" {
		t.Errorf("AllowedOrigins = %v, want [*]: an unset origin list allows "+
			"every origin, and an operator reading \"none\" would not know that",
			got.AllowedOrigins)
	}
	if len(got.AllowedMethods) == 0 {
		t.Error("AllowedMethods is empty; the enforced default is GET/POST/HEAD")
	}
	if len(got.AllowedHeaders) == 0 {
		t.Error("AllowedHeaders is empty; the enforced default is not")
	}

	// A configured list must be reported verbatim, not merged with the default.
	set := corsEffectivePolicy(CORSConfig{AllowedOrigins: []string{"https://a"}})
	if len(set.AllowedOrigins) != 1 || set.AllowedOrigins[0] != "https://a" {
		t.Errorf("AllowedOrigins = %v, want the configured list unchanged", set.AllowedOrigins)
	}
}
