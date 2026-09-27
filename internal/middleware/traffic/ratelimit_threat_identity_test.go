// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// rateLimitedClient is one client of one key strategy: its own address, so the
// cases cannot see each other's scores, and the fingerprint the entrypoint
// would have resolved for it.
type rateLimitedClient struct {
	strategy string
	key      func(*http.Request) string
	ip       string
}

// request builds a request as the entrypoint leaves it for the chain.
func (c rateLimitedClient) request() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/orders", nil)
	req.RemoteAddr = c.ip + ":43000"
	rs := &request.RequestState{
		JA4Plus: "t13d1516h2_rl_" + c.strategy + "_ja4plus",
		JA4H:    "ge11nn05enus_rl_" + c.strategy,
	}
	return req.WithContext(request.WithState(req.Context(), rs))
}

// rejectOnce sends two requests through a limiter that allows one, so the
// second is refused and recorded as a threat.
func rejectOnce(t *testing.T, c rateLimitedClient) {
	t.Helper()
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := NewRateLimiter(0.0001, 1).Handler(c.key)(ok)
	codes := [2]int{}
	for i := range codes {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, c.request())
		codes[i] = rr.Code
	}
	if codes != [2]int{http.StatusOK, http.StatusTooManyRequests} {
		t.Fatalf("setup: the limiter answered %v, want [200 429]", codes)
	}
}

// recordedRateLimitSource waits for the rate-limit threat about key and
// returns the source it was recorded under.
func recordedRateLimitSource(t *testing.T, ch <-chan telemetry.SecurityThreat, marker string) string {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case th := <-ch:
			if th.Type == "rate_limit" && th.Fingerprint == marker {
				return th.SourceIP
			}
		case <-deadline:
			t.Fatalf("setup: no rate_limit threat was recorded for %s", marker)
			return ""
		}
	}
}

// TestRateLimitThreatsAreScoredWhereTheBlockerReads is the regression test for
// rate-limit penalties recorded against something that is not an address.
//
// A refused request is recorded as a threat whose source was the limiter's key.
// Under the default "ip" strategy that is the client's address, but under
// "tenant" it is a tenant id or "ip:<address>", and under "ja4h" and
// "fingerprint" it is already a fingerprint scoped to a network. The store
// scopes a threat's reputation penalty to the network of its source address, so
// those penalties landed under keys like "<ja4+>|<ja4h>|203.0.113" that the
// reputation blocker -- and the adaptive limit itself -- never read: a client
// could be refused all day under those strategies without its reputation
// moving. The same source is what the dashboard shows, what the correlation
// engine groups by and what an operator's release looks up.
func TestRateLimitThreatsAreScoredWhereTheBlockerReads(t *testing.T) {
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "telemetry.db"), 1); err != nil {
		t.Fatalf("InitPathStatsStore: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })
	threats := telemetry.ThreatBroadcaster.Subscribe()
	t.Cleanup(func() { telemetry.ThreatBroadcaster.Unsubscribe(threats) })

	for _, c := range []rateLimitedClient{
		{strategy: "ip", key: PerIP, ip: "203.0.113.121"},
		{strategy: "tenant", key: PerTenant, ip: "203.0.113.122"},
		{strategy: "ja4h", key: PerJA4H, ip: "203.0.113.123"},
		{strategy: "fingerprint", key: PerFingerprint, ip: "203.0.113.124"},
	} {
		t.Run(c.strategy, func(t *testing.T) {
			probe := c.request()
			repID := telemetry.GetReputationID(probe)
			t.Cleanup(func() { telemetry.ResetReputation(repID) })

			rejectOnce(t, c)
			telemetry.FlushThreats()

			fp := request.GetRequestState(probe).JA4Plus
			if src := recordedRateLimitSource(t, threats, fp); src != c.ip {
				t.Errorf("the rejection was recorded as coming from %q, want the client's address %q", src, c.ip)
			}
			if got := telemetry.GetReputationScore(repID); got >= 100 {
				t.Errorf("after a %s-keyed rejection the reputation the blocker reads (%s) is still %v: "+
					"the penalty was recorded under a key nothing reads", c.strategy, repID, got)
			}
		})
	}
}
