// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/middleware/security"
	"github.com/gsoultan/gateon/internal/middleware/security/identity"
	"github.com/gsoultan/gateon/internal/request"
	secwaf "github.com/gsoultan/gateon/internal/security/waf"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// These tests drive a route WAF built by the factory a route uses, behind the
// reputation blocker every route carries, with the real threat recording path
// behind it. Each is a way an innocent client was refused (ADR 0055): what
// the WAF did not refuse, and what the server sent, were held against the
// client that sent the request.

// stockBuild is one browser build; every user of it presents this JA4+.
const stockBuild = "t13d1516h2_8daaf6152771_b0da82dd1658_ge11cr0200_7e33b58890ac"

// innocentPage is what the origin answers: a receipt carrying a card number,
// which a response DLP rule matches.
const innocentPage = `<html><body>Your order: card ` + leakVisa + ` was charged.</body></html>`

// plainPage is an answer nothing matches.
const plainPage = `<html><body>hello</body></html>`

// innocentRoute builds a route WAF from cfg (nil: storeBackedWAF) over an origin answering page,
// behind the reputation blocker, with reputation enabled and a telemetry store
// of its own. It returns the route and a subscription to every threat recorded.
func innocentRoute(t *testing.T, cfg map[string]string, page string) (http.Handler, chan telemetry.SecurityThreat) {
	t.Helper()
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "innocent.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(t.Context()) })
	threats := telemetry.ThreatBroadcaster.Subscribe()
	t.Cleanup(func() { telemetry.ThreatBroadcaster.Unsubscribe(threats) })

	var (
		mw  kind.Middleware
		err error
	)
	if cfg != nil {
		cfg["route_id"] = t.Name()
		mw, err = NewWAF(cfg, security.Deps{})
	} else {
		mw, err = storeBackedWAF(t)
	}
	if err != nil {
		t.Fatalf("build WAF: %v", err)
	}
	origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Length", strconv.Itoa(len(page)))
		_, _ = w.Write([]byte(page))
	})
	return identity.ReputationBlocker(t.Name())(mw(origin)), threats
}

// storeBackedWAF is an enforcing WAF with DLP over the seeded rule store, as a
// gateway's is: the inbound data-leak corpus is loaded from the store, which
// the route factory reaches through a process-wide handle tests cannot set.
func storeBackedWAF(t *testing.T) (kind.Middleware, error) {
	t.Helper()
	d, dialect, err := db.Open("sqlite::memory:")
	if err != nil {
		return nil, err
	}
	if err := db.Migrate(d, dialect); err != nil {
		return nil, err
	}
	store := secwaf.NewStore(d)
	if err := store.Seed(t.Context()); err != nil {
		return nil, err
	}
	return WAF(WAFConfig{
		EnableDLP: true, ParanoiaLevel: 2, RouteID: t.Name(), WafRules: store,
		RequestBodyLimit: 1 << 20, DisableWordPress: true,
	})
}

// visit sends one request from ip with stockBuild, waits for the threats it
// produced to be processed, and returns what the client got.
func visit(t *testing.T, h http.Handler, ip string, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	req.RemoteAddr = ip + ":40000"
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "+
		"(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
	req = req.WithContext(request.WithState(req.Context(), &request.RequestState{JA4Plus: stockBuild}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	telemetry.FlushThreats()
	return rr
}

// recorded drains the threats recorded so far.
func recorded(threats chan telemetry.SecurityThreat) []telemetry.SecurityThreat {
	var out []telemetry.SecurityThreat
	for len(threats) > 0 {
		out = append(out, <-threats)
	}
	return out
}

func scoreOf(ip string) float64 {
	return telemetry.GetReputationScore(repid.For(stockBuild, ip))
}

func xssProbe() *http.Request {
	return httptest.NewRequest(http.MethodGet, "/search?q="+url.QueryEscape("<script>alert(1)</script>"), nil)
}

// TestAnAuditOnlyWAFNeverRefusesItsClients is TRUTH-NEW-2. The route says
// "Record matched rules and block nothing", and every match took 50 off the
// client's score: the third request with a false positive, on this route or
// any other, was refused.
func TestAnAuditOnlyWAFNeverRefusesItsClients(t *testing.T) {
	const client = "203.0.113.30"
	h, threats := innocentRoute(t, map[string]string{"audit_only": "true"}, plainPage)
	t.Cleanup(func() { telemetry.ResetReputation(repid.For(stockBuild, client)) })

	for i := range 4 {
		if rr := visit(t, h, client, xssProbe()); rr.Code != http.StatusOK {
			t.Fatalf("request %d through an audit-only WAF got %d (%q)", i+1, rr.Code, rr.Body.String())
		}
	}
	if got := scoreOf(client); got != 100 {
		t.Errorf("an audit-only WAF's matches moved the client's score to %v", got)
	}
	if len(recorded(threats)) == 0 {
		t.Fatal("the audit-only WAF recorded nothing, so the assertions above prove nothing")
	}
}

// TestAnAuditOnlyWAFDoesNotRefuseOnItsFastPathChecks: the protocol check
// honoured audit-only; the token, entropy and client-consistency checks
// refused anyway.
func TestAnAuditOnlyWAFDoesNotRefuseOnItsFastPathChecks(t *testing.T) {
	const client = "203.0.113.31"
	h, threats := innocentRoute(t, map[string]string{"audit_only": "true"}, plainPage)
	t.Cleanup(func() { telemetry.ResetReputation(repid.For(stockBuild, client)) })

	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.not-a-jwt-payload-at-all")
	if rr := visit(t, h, client, req); rr.Code != http.StatusOK {
		t.Fatalf("an audit-only WAF refused a malformed token with %d (%q)", rr.Code, rr.Body.String())
	}
	if got := scoreOf(client); got != 100 {
		t.Errorf("an audit-only fast-path match moved the client's score to %v", got)
	}
	if len(recorded(threats)) == 0 {
		t.Fatal("the fast-path check recorded nothing, so the assertions above prove nothing")
	}
}

// TestAMatchTheWAFDidNotRefuseLeavesTheClientAlone: an enforcing WAF's
// log-only rules -- the inbound data-leak corpus, which records a secret
// someone pasted and never refuses -- cost the client 50 each. A user pasting
// an example key into two support tickets was refused everywhere.
func TestAMatchTheWAFDidNotRefuseLeavesTheClientAlone(t *testing.T) {
	const client = "203.0.113.32"
	h, threats := innocentRoute(t, nil, plainPage)
	t.Cleanup(func() { telemetry.ResetReputation(repid.For(stockBuild, client)) })

	for i := range 3 {
		req := httptest.NewRequest(http.MethodPost, "/support/tickets",
			strings.NewReader(`{"message":"deploy is broken, key is AKIAIOSFODNN7EXAMPLE"}`))
		req.Header.Set("Content-Type", "application/json")
		if rr := visit(t, h, client, req); rr.Code != http.StatusOK {
			t.Fatalf("ticket %d got %d (%q)", i+1, rr.Code, rr.Body.String())
		}
	}
	if got := scoreOf(client); got != 100 {
		t.Errorf("matches the WAF did not refuse moved the client's score to %v", got)
	}
	if len(recorded(threats)) == 0 {
		t.Fatal("no match was recorded, so the assertions above prove nothing")
	}
}

// TestADataLeakInAResponseNeverRefusesItsReader is TRUTH-NEW-3: a DLP finding
// in a response was filed as a WAF block against the reader, so the third view
// of a redacted receipt was a reputation block on every route.
func TestADataLeakInAResponseNeverRefusesItsReader(t *testing.T) {
	for _, action := range []string{"redact", "block", "audit"} {
		t.Run(action, func(t *testing.T) {
			const reader = "203.0.113.40"
			h, threats := innocentRoute(t, map[string]string{"dlp": "true", "dlp_action": action}, innocentPage)
			t.Cleanup(func() { telemetry.ResetReputation(repid.For(stockBuild, reader)) })

			for i := range 4 {
				rr := visit(t, h, reader, httptest.NewRequest(http.MethodGet, "/orders/1", nil))
				if strings.Contains(rr.Body.String(), "Reputation Block") {
					t.Fatalf("view %d: the reader was refused by reputation", i+1)
				}
				if action != "block" && rr.Code != http.StatusOK {
					t.Fatalf("view %d got %d (%q)", i+1, rr.Code, rr.Body.String())
				}
			}
			if got := scoreOf(reader); got != 100 {
				t.Errorf("a leak in the response moved the reader's score to %v", got)
			}
			assertAnExposureOnTheRoute(t, recorded(threats), reader)
		})
	}
}

// assertAnExposureOnTheRoute checks the leak was recorded -- so the test is not
// passing because DLP matched nothing -- as an event on the route that names
// no source and says whom the response was for.
func assertAnExposureOnTheRoute(t *testing.T, threats []telemetry.SecurityThreat, reader string) {
	t.Helper()
	var exposures int
	for _, th := range threats {
		if th.SourceIP == reader {
			t.Errorf("a %s record names the reader as its source", th.Type)
		}
		if th.Type == "data_exposure" {
			exposures++
			if th.RouteID != t.Name() || !strings.Contains(th.Details, reader) {
				t.Errorf("exposure record route %q details %q", th.RouteID, th.Details)
			}
		}
	}
	if exposures == 0 {
		t.Fatalf("no data exposure was recorded (%d threats), so the assertions above prove nothing", len(threats))
	}
}

// TestAnAttackerIsStillRefused is the other half: a client the WAF refuses
// for what it sent loses its score on its own network, and is refused there.
func TestAnAttackerIsStillRefused(t *testing.T) {
	const attacker, elsewhere = "198.18.5.5", "203.0.113.11"
	h, _ := innocentRoute(t, map[string]string{"audit_only": "false"}, plainPage)
	t.Cleanup(func() { telemetry.ResetReputation(repid.For(stockBuild, attacker)) })

	for i := range 2 {
		if rr := visit(t, h, attacker, xssProbe()); rr.Code != http.StatusForbidden {
			t.Fatalf("attack %d got %d, want the WAF's 403", i+1, rr.Code)
		}
	}
	rr := visit(t, h, attacker, httptest.NewRequest(http.MethodGet, "/home", nil))
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "Reputation Block") {
		t.Errorf("the attacker's next ordinary request got %d (%q), want a reputation block", rr.Code, rr.Body.String())
	}
	if rr := visit(t, h, elsewhere, httptest.NewRequest(http.MethodGet, "/home", nil)); rr.Code != http.StatusOK {
		t.Errorf("a user of the same build on another network got %d", rr.Code)
	}
}
