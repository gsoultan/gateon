// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// asPreflight gives a request the shape kind.IsCorsPreflight recognises. Every
// one of the three values is written by the client, which is the whole point:
// before the fix these were the credentials for skipping a deny decision.
func asPreflight(r *http.Request) *http.Request {
	r.Header.Set("Origin", "https://evil.example")
	r.Header.Set("Access-Control-Request-Method", "GET")
	return r
}

// TestIPMitigationRefusesAPreflightFromAShunnedIP closes the first half of a
// bypass that was live on the smart-TCP listener.
//
// A CORS middleware answered preflights ahead of the HTTP entrypoint's chain
// when this was found (removed since, ADR-0015), so there the skip below was
// unreachable. buildPlainHTTPHandler did not include it -- so on a plaintext
// smart-TCP entrypoint a shunned address reached deps.BaseHandler, and from
// there the route chain, by sending OPTIONS with two headers.
func TestIPMitigationRefusesAPreflightFromAShunnedIP(t *testing.T) {
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "ipmit.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	defer telemetry.ClosePathStatsStore(t.Context())

	// An address of this test's own, so the mitigation it sets is not an
	// identity any other test in the package resolves to.
	const shunned = "198.51.100.23"
	telemetry.MarkIPMitigated(shunned, "preflight enforcement test")
	defer telemetry.MarkIPUnmitigated(shunned)

	var reached bool
	h := IPMitigation()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := withState(asPreflight(httptest.NewRequest(http.MethodOptions, "/", nil)),
		&request.RequestState{ClientRemoteAddr: shunned})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if reached {
		t.Error("a preflight from a shunned IP reached the backend; the shun " +
			"is opt-out by writing three values the client chooses")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

// TestIPMitigationStillAllowsAPreflightFromACleanIP is the other half: the fix
// must not turn legitimate browser CORS into a refusal.
func TestIPMitigationStillAllowsAPreflightFromACleanIP(t *testing.T) {
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "ipmit-ok.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	defer telemetry.ClosePathStatsStore(t.Context())

	var reached bool
	h := IPMitigation()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := withState(asPreflight(httptest.NewRequest(http.MethodOptions, "/", nil)),
		&request.RequestState{ClientRemoteAddr: "198.51.100.24"})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !reached {
		t.Errorf("a preflight from an unmitigated IP was refused with %d; the "+
			"fix must only affect clients that were already being denied", rr.Code)
	}
}

// TestUserMitigationRefusesAPreflightFromAMitigatedFingerprint is the second
// half of the smart-TCP bypass: UserMitigation sits directly after
// IPMitigation in that chain and carried the same exemption.
func TestUserMitigationRefusesAPreflightFromAMitigatedFingerprint(t *testing.T) {
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "usermit.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	defer telemetry.ClosePathStatsStore(t.Context())

	const fp = "t13d1516h2_preflight_enforcement_test"
	telemetry.MarkUserMitigated(fp, "JA4", "preflight enforcement test", "test")
	defer telemetry.MarkUserUnmitigated(fp)

	var reached bool
	h := UserMitigation()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	// Not one of unmitigatedPaths -- that exemption is a path the gateway
	// chooses to answer, which is a different thing from a shape the caller
	// names, and it deliberately stays.
	req := withState(asPreflight(httptest.NewRequest(http.MethodOptions, "/", nil)),
		&request.RequestState{JA4Plus: fp})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if reached {
		t.Error("a preflight from a mitigated fingerprint reached the backend")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

// TestReputationBlockerRefusesAPreflightFromAZeroScoreClient covers the route
// chain, which a preflight reached through BaseHandler once the two above had
// waved it past.
func TestReputationBlockerRefusesAPreflightFromAZeroScoreClient(t *testing.T) {
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "rep-preflight.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	defer telemetry.ClosePathStatsStore(t.Context())

	req := withState(asPreflight(httptest.NewRequest(http.MethodOptions, "/", nil)), &request.RequestState{})
	// A network of its own, for the reason reputation_severity_test.go gives.
	req.RemoteAddr = "198.51.100.91:4321"
	id := telemetry.GetReputationID(req)
	telemetry.DecreaseReputation(id, 100, "preflight enforcement test")
	defer telemetry.ResetReputation(id)

	rr := httptest.NewRecorder()
	ReputationBlocker("preflight-route")(okOrigin()).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("a preflight from a client at reputation 0 got %d, want %d",
			rr.Code, http.StatusForbidden)
	}
}
