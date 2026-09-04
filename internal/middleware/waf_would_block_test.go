// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/security/waf"
)

// These tests cover gateon_middleware_waf_would_block_total, the counter that
// makes audit-only a measurement rather than an off switch.
//
// Before it existed, audit-only produced a 200 and a threat-list entry, and
// nothing anywhere answered the only question an operator actually has: how many
// real users would have seen a block page if I turned this on? That left two
// choices, enforce blind or never enforce, and the second is what most
// deployments picked.
//
// The counter has to be right in both directions to be worth having. Counting
// too little tells an operator enforcement is safe when it is not. Counting too
// much predicts an outage that was never going to happen, which is just as
// effective at keeping the WAF switched off.

// auditOnlyHandler builds a WAF that detects and never refuses.
func auditOnlyHandler(t *testing.T, routeID string, dlp bool) http.Handler {
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
		AuditOnly:        true,
		EnableDLP:        dlp,
		ParanoiaLevel:    2,
		RouteID:          routeID,
		WafRules:         store,
		RequestBodyLimit: 1024 * 1024,
		DisableWordPress: true,
	})
	if err != nil {
		t.Fatalf("create audit-only WAF: %v", err)
	}
	return mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

// serveAudit drives one request and reports the status the client saw.
func serveAudit(h http.Handler, method, target, contentType, body string) int {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "+
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
	req = req.WithContext(context.WithValue(req.Context(),
		request.RequestStateContextKey{}, &request.RequestState{}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

// wouldBlockCount sums gateon_middleware_waf_would_block_total for one route.
//
// It reads the gathered registry rather than a named series, so the test never
// has to name the rule that fires. gwaf detects structurally, and pinning a rule
// id would assert which rule caught a payload rather than that the payload was
// caught — the reasoning waf_corpus_test.go gives for testing shapes, not ids.
//
// Gathering directly also keeps prometheus/testutil out of go.mod. Reaching for
// a test-only dependency to read one float is not a trade worth making on a
// project that builds CGO-free onto distroless.
func wouldBlockCount(t *testing.T, routeID string) float64 {
	t.Helper()

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	var total float64
	for _, f := range families {
		if f.GetName() != "gateon_middleware_waf_would_block_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "route" && l.GetValue() == routeID {
					total += m.GetCounter().GetValue()
				}
			}
		}
	}
	return total
}

// TestWouldBlockCountsAuditOnlyRefusals is the positive half.
//
// An attack through an audit-only WAF must reach the backend — that is what
// audit-only means — and must still be counted, because the count is the whole
// reason to run in that mode.
func TestWouldBlockCountsAuditOnlyRefusals(t *testing.T) {
	const routeID = "would-block-positive"
	h := auditOnlyHandler(t, routeID, false)

	before := wouldBlockCount(t, routeID)

	// A payload the corpus already proves is refused when enforcing
	// (TestWAFCorpus_AttacksBlocked).
	if got := serveAudit(h, http.MethodGet, "/?id=1%20OR%201=1--", "", ""); got != http.StatusOK {
		t.Fatalf("audit-only returned %d, want 200 — audit-only must not refuse; "+
			"if this blocks, AuditOnly has stopped reaching the engine", got)
	}

	after := wouldBlockCount(t, routeID)
	if after <= before {
		t.Errorf("would-block counter did not move (%v → %v) on a payload that blocks "+
			"when enforcing.\nAudit-only reports success while measuring nothing, which "+
			"is the state this counter exists to end.", before, after)
	}
}

// TestWouldBlockIgnoresLogOnlyRules is the negative half, and the one that
// decides whether the number can be trusted.
//
// The inbound data-leak rules carry action rules.Log: they record a secret
// someone pasted and deliberately never refuse the request, because refusing a
// POST throws away what the user typed and teaches them to route around the
// gateway (mem:dlp). Those rules would still block nothing if enforcement were
// switched on, so counting them here would tell an operator to expect refusals
// that cannot happen — and an inflated estimate keeps a WAF in detection mode
// exactly as effectively as a real outage would.
func TestWouldBlockIgnoresLogOnlyRules(t *testing.T) {
	const routeID = "would-block-log-only"
	h := auditOnlyHandler(t, routeID, true)

	before := wouldBlockCount(t, routeID)

	// A leaked AWS key inbound: matches rule 1131xxx, which logs and never blocks.
	body := `{"message":"deploy is broken, key is AKIAIOSFODNN7EXAMPLE"}`
	if got := serveAudit(h, http.MethodPost, "/support/tickets", "application/json", body); got != http.StatusOK {
		t.Fatalf("inbound DLP returned %d, want 200 — these rules log and never block", got)
	}

	if after := wouldBlockCount(t, routeID); after != before {
		t.Errorf("would-block counter moved (%v → %v) for a log-only rule.\n"+
			"These rules never refuse anything, so counting them overstates what "+
			"enforcement would cost and argues against a change that is in fact safe.",
			before, after)
	}
}

// TestWouldBlockIsSilentOnCleanTraffic guards the base rate.
//
// A counter that ticks on ordinary requests would put the estimate somewhere
// near the request rate, and an operator reading "we would have blocked
// everything" learns nothing and stops looking.
func TestWouldBlockIsSilentOnCleanTraffic(t *testing.T) {
	const routeID = "would-block-clean"
	h := auditOnlyHandler(t, routeID, false)

	before := wouldBlockCount(t, routeID)

	for _, target := range []string{
		"/",
		"/products?page=2&sort=price",
		"/orders/7c9e6679-7425-40de-944b-e07fc1f90ae7",
		"/search?q=select+a+plan",
	} {
		if got := serveAudit(h, http.MethodGet, target, "", ""); got != http.StatusOK {
			t.Fatalf("%s returned %d, want 200", target, got)
		}
	}

	if after := wouldBlockCount(t, routeID); after != before {
		t.Errorf("would-block counter moved (%v → %v) on ordinary traffic; the "+
			"estimate is only useful if its base rate is zero", before, after)
	}
}

// TestEnforcingModeDoesNotCountWouldBlock keeps the two counters from
// double-reporting.
//
// When the WAF is enforcing, a refusal is a refusal and belongs in
// gateon_middleware_waf_blocked_total. Incrementing both would make a dashboard
// that sums them report twice the traffic, and an operator comparing
// before-and-after an enforcement change would see the would-block figure stay
// flat instead of dropping to zero — the exact signal they are looking for.
func TestEnforcingModeDoesNotCountWouldBlock(t *testing.T) {
	const routeID = "would-block-enforcing"

	mw, err := WAF(WAFConfig{
		ParanoiaLevel:    1,
		RouteID:          routeID,
		DisableWordPress: true,
	})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	before := wouldBlockCount(t, routeID)

	if got := serveAudit(h, http.MethodGet, "/?id=1%20OR%201=1--", "", ""); got != http.StatusForbidden {
		t.Fatalf("enforcing WAF returned %d, want 403", got)
	}

	if after := wouldBlockCount(t, routeID); after != before {
		t.Errorf("would-block counter moved (%v → %v) while enforcing; a real block "+
			"belongs in waf_blocked_total only, or every dashboard that sums the two "+
			"reports double", before, after)
	}
}
