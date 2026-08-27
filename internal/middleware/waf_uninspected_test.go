// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/security/waf"
	"github.com/gsoultan/gateon/internal/telemetry"
	dto "github.com/prometheus/client_model/go"
)

// uninspectedCount reads the coverage counter for one route and reason.
//
// Read through the collector rather than prometheus/testutil, which would pull
// a module into go.mod for the sake of one assertion.
func uninspectedCount(t *testing.T, route, reason string) float64 {
	t.Helper()
	c, err := telemetry.MiddlewareWAFUninspectedResponsesTotal.GetMetricWithLabelValues(route, reason)
	if err != nil {
		t.Fatalf("counter: %v", err)
	}
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	return m.GetCounter().GetValue()
}

// inspectingWAF builds a response-inspecting WAF on the named route.
func inspectingWAF(t *testing.T, routeID string) Middleware {
	t.Helper()
	d, dialect, err := db.Open("sqlite::memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Migrate(d, dialect); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := waf.NewStore(d)
	if err := store.Seed(t.Context()); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	mw, err := WAF(WAFConfig{
		EnableDLP:                true,
		EnableResponseInspection: true,
		RouteID:                  routeID,
		WafRules:                 store,
		ResponseBodyLimit:        1024 * 1024,
		RequestBodyLimit:         1024 * 1024,
	})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}
	return mw
}

// TestUninspectedResponseIsCounted is the coverage signal. A response that was
// inspected and found clean and a response nobody could read produce the same
// 200 and the same silence everywhere else, so without this counter an operator
// reads "no findings" as "no leaks" when it may mean "never looked".
func TestUninspectedResponseIsCounted(t *testing.T) {
	const route = "test-uninspected-counted"
	before := uninspectedCount(t, route, reasonUndecodableEncoding)

	// An origin that ignores the negotiated Accept-Encoding and answers in
	// something this build cannot undo.
	handler := inspectingWAF(t, route)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "br")
		_, _ = w.Write([]byte("\x1b\x2e\x00\x00opaque-to-this-build"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := uninspectedCount(t, route, reasonUndecodableEncoding); got != before+1 {
		t.Errorf("counter went from %v to %v, want %v", before, got, before+1)
	}
	// The response still reaches the client: an unreadable body is a coverage
	// gap to report, not grounds to refuse traffic the origin considers fine.
	if rec.Code != http.StatusOK {
		t.Errorf("uninspectable response was blocked: status %d", rec.Code)
	}
}

// TestUninspectedWarningIsPerRouteNotPerProcess is the regression for the bug
// this replaced. A single process-wide sync.Once meant whichever route hit the
// blind spot first was the only one an operator ever heard about — every other
// route's gap was silent for the life of the process.
func TestUninspectedWarningIsPerRouteNotPerProcess(t *testing.T) {
	routes := []string{"test-warn-route-a", "test-warn-route-b"}
	for _, r := range routes {
		uninspectedWarned.Delete(r + "\x00" + reasonUndecodableEncoding)
	}

	for _, route := range routes {
		handler := inspectingWAF(t, route)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Encoding", "br")
			_, _ = w.Write([]byte("opaque"))
		}))
		req := httptest.NewRequest(http.MethodGet, "/page", nil)
		req.Header.Set("Accept-Encoding", "br")
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	for _, route := range routes {
		if _, warned := uninspectedWarned.Load(route + "\x00" + reasonUndecodableEncoding); !warned {
			t.Errorf("route %q never warned about its inspection gap", route)
		}
	}
}

// TestUninspectedWarningIsLoggedOnce keeps the other half honest: an origin
// misconfigured for every response it serves must not write a log line per
// response, which is how a real signal gets buried.
func TestUninspectedWarningIsLoggedOnce(t *testing.T) {
	const route = "test-warn-once"
	key := route + "\x00" + reasonUndecodableEncoding
	uninspectedWarned.Delete(key)

	handler := inspectingWAF(t, route)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "br")
		_, _ = w.Write([]byte("opaque"))
	}))

	before := uninspectedCount(t, route, reasonUndecodableEncoding)
	const responses = 5
	for range responses {
		req := httptest.NewRequest(http.MethodGet, "/page", nil)
		req.Header.Set("Accept-Encoding", "br")
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	// Counted every time, so the rate is visible...
	if got := uninspectedCount(t, route, reasonUndecodableEncoding); got != before+responses {
		t.Errorf("counter went from %v to %v, want %v", before, got, before+responses)
	}
	// ...and the warn-tracking key exists exactly once regardless.
	if _, warned := uninspectedWarned.Load(key); !warned {
		t.Error("the first uninspectable response did not warn")
	}
}
