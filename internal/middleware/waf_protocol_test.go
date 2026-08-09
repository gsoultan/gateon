// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// These cover the coverage that moved out of the rule engine when the OWASP
// CRS was removed. Each case names the CRS rule it stands in for, so the
// mapping is checkable rather than remembered.

func TestProtocolEnforcement(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		method  string
		headers map[string][]string
		want    int // 0 means the request must be allowed
	}{
		{name: "ordinary GET", method: http.MethodGet, want: 0},
		{name: "ordinary POST", method: http.MethodPost, want: 0},
		{name: "CORS preflight is still allowed", method: http.MethodOptions, want: 0},

		// CRS 911: method enforcement.
		{name: "TRACE is refused", method: "TRACE", want: http.StatusMethodNotAllowed},
		{name: "CONNECT is refused", method: "CONNECT", want: http.StatusMethodNotAllowed},
		{name: "an invented method is refused", method: "WHATEVER", want: http.StatusMethodNotAllowed},

		// CRS 1120012 / 1150002: conflicting framing, the start of request
		// smuggling.
		{
			name:   "duplicate Content-Length",
			method: http.MethodPost,
			// Go joins repeated headers, so the smuggling attempt arrives as
			// one comma-separated value. Checking only for len(values) > 1
			// would miss it entirely.
			headers: map[string][]string{"Content-Length": {"5, 10"}},
			want:    http.StatusBadRequest,
		},
		{
			name:    "duplicate Content-Type",
			method:  http.MethodPost,
			headers: map[string][]string{"Content-Type": {"application/json", "text/plain"}},
			want:    http.StatusBadRequest,
		},

		// CRS 1120011: header name length.
		{
			name:    "over-long header name",
			method:  http.MethodGet,
			headers: map[string][]string{strings.Repeat("A", maxHeaderNameLength+1): {"x"}},
			want:    http.StatusRequestHeaderFieldsTooLarge,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mw, err := WAF(WAFConfig{})
			if err != nil {
				t.Fatalf("create WAF: %v", err)
			}
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(tc.method, "/", nil)
			for name, values := range tc.headers {
				req.Header[name] = values
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if tc.want == 0 {
				if rr.Code != http.StatusOK {
					t.Errorf("conforming request refused with %d", rr.Code)
				}
				return
			}
			if rr.Code != tc.want {
				t.Errorf("status = %d, want %d", rr.Code, tc.want)
			}
		})
	}
}

// TestGRPCIsNotRefusedByProtocolChecks is the regression test for the whole
// reason the gRPC compat directives existed.
//
// The CRS content-type allowlist refused every gRPC request, so gateon had to
// inject rules widening it and then disable body inspection for gRPC entirely.
// None of that is reproduced here, and this proves it: a gRPC request passes
// protocol enforcement with its body still subject to inspection.
func TestGRPCIsNotRefusedByProtocolChecks(t *testing.T) {
	t.Parallel()

	mw, err := WAF(WAFConfig{})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, ct := range []string{
		"application/grpc",
		"application/grpc+proto",
		"application/grpc-web+proto",
		"application/grpc-web-text",
	} {
		req := httptest.NewRequest(http.MethodPost, "/pkg.Service/Method",
			strings.NewReader("\x00\x00\x00\x00\x05hello"))
		req.Header.Set("Content-Type", ct)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("gRPC request with content type %q refused with %d", ct, rr.Code)
		}
	}
}

func TestAllowedMethodsIsConfigurable(t *testing.T) {
	t.Parallel()

	mw, err := WAF(WAFConfig{AllowedMethods: parseAllowedMethods("GET, HEAD")})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("GET refused by an allowlist containing it: %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST allowed by an allowlist that omits it: %d", rr.Code)
	}
}

func TestParseAllowedMethods(t *testing.T) {
	t.Parallel()

	got := parseAllowedMethods(" get , Post ,, DELETE ")
	for _, m := range []string{"GET", "POST", "DELETE"} {
		if !got[m] {
			t.Errorf("method %q missing from %v", m, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("parsed %d methods, want 3: %v", len(got), got)
	}
	// An empty setting must mean "use the default set", not "allow nothing" —
	// the latter would refuse every request on any install that never
	// configured it.
	if parseAllowedMethods("  ") != nil {
		t.Error("an empty configuration produced a non-nil allowlist")
	}
}
