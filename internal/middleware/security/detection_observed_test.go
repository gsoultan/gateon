// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/middleware/security/identity"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// ADR 0059: a request the gateway let through is not evidence against its
// client. Each test here drives a detection-only middleware behind the
// enforcement every route carries, with the real threat recording path and
// reputation enabled, and sends the same client more matching requests than
// it took, before, for the reputation blocker to refuse it on every route.

// detectingBuild is one browser build; every user of it presents this JA4+.
const detectingBuild = "t13d1516h2_8daaf6152771_b0da82dd1658_ge11cr0200_7e33b58890ac"

// requestsToExhaust is more matching requests than any of these middlewares'
// scores needed to take a client from 100 to the blocker's floor when each
// cost half its score: the cheapest, XSS at 50, needed four.
const requestsToExhaust = 6

// detectionStore gives the test a telemetry store of its own, with reputation
// enabled, and a subscription to every threat recorded.
func detectionStore(t *testing.T) chan telemetry.SecurityThreat {
	t.Helper()
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "detection.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(t.Context()) })
	threats := telemetry.ThreatBroadcaster.Subscribe()
	t.Cleanup(func() { telemetry.ThreatBroadcaster.Unsubscribe(threats) })
	return threats
}

// enforcedRoute is mw over an origin answering 200, behind the enforcement
// every route carries, in router.go's order.
func enforcedRoute(routeID string, mw kind.Middleware) http.Handler {
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})
	return kind.Chain(
		identity.IPMitigation(),
		identity.UserMitigation(),
		identity.ReputationBlocker(routeID),
		mw,
	)(origin)
}

// sendAs serves one request as ip with detectingBuild, waits for the threats
// it produced to be processed, and returns the status the client got.
func sendAs(h http.Handler, ip string, req *http.Request) int {
	req.RemoteAddr = ip + ":40000"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "+
		"(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
	req = req.WithContext(request.WithState(req.Context(), &request.RequestState{JA4Plus: detectingBuild}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	telemetry.FlushThreats()
	return rr.Code
}

// drained returns the threats recorded so far.
func drained(threats chan telemetry.SecurityThreat) []telemetry.SecurityThreat {
	var out []telemetry.SecurityThreat
	for len(threats) > 0 {
		out = append(out, <-threats)
	}
	return out
}

func detectingScore(ip string) float64 {
	return telemetry.GetReputationScore(repid.For(detectingBuild, ip))
}

func randomBody(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4096)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestADetectionTheGatewayLetThroughNeverRefusesItsClient: the recognition
// middlewares and the body entropy check record a finding and pass the
// request on. Each finding took half its score off the client's reputation,
// so the fourth request carrying "<img", "update " or "--" -- or a compressed
// upload -- was refused, on that route and every other. The management plane
// runs the same three recognisers.
func TestADetectionTheGatewayLetThroughNeverRefusesItsClient(t *testing.T) {
	cases := []struct {
		name string
		mw   kind.Middleware
		req  func(t *testing.T) *http.Request
	}{
		{"xss", XSSRecognition("xss-route"), func(*testing.T) *http.Request {
			return httptest.NewRequest(http.MethodGet, "/gallery?caption=%3Cimg%20src%3Dcat.png%3E", nil)
		}},
		{"sqli on the management plane", SQLiRecognition("gateon-management"), func(*testing.T) *http.Request {
			r := httptest.NewRequest(http.MethodPost, "/v1/routes",
				strings.NewReader(`{"name":"api--v2","notes":"update the backend first"}`))
			r.Header.Set("Content-Type", "application/json")
			return r
		}},
		{"threat recognition on the management plane", ThreatRecognition("gateon-management"), func(*testing.T) *http.Request {
			return httptest.NewRequest(http.MethodGet, "/v1/search?q=casino%20night%20poker", nil)
		}},
		{"body entropy", Entropy(4.0, "upload-route"), func(t *testing.T) *http.Request {
			return httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(randomBody(t)))
		}},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			threats := detectionStore(t)
			client := fmt.Sprintf("100.64.%d.10", 10+i)
			t.Cleanup(func() { telemetry.ResetReputation(repid.For(detectingBuild, client)) })
			h := enforcedRoute("route-"+tc.name, tc.mw)

			for n := range requestsToExhaust {
				if code := sendAs(h, client, tc.req(t)); code != http.StatusOK {
					t.Fatalf("request %d, which the %s check let through, was refused with %d: "+
						"the detections before it were held against the client", n+1, tc.name, code)
				}
			}
			if got := detectingScore(client); got != 100 {
				t.Errorf("detections the gateway let through moved the client's score to %v", got)
			}
			seen := drained(threats)
			if len(seen) == 0 {
				t.Fatal("nothing was recorded, so the assertions above prove nothing")
			}
			for _, th := range seen {
				if th.HeldAgainstSource() {
					t.Errorf("%s (action %q) is held against its source", th.Type, th.ActionTaken)
				}
			}
		})
	}
}

// TestATrapStillRefusesTheClientEverywhere is the control: a request the
// gateway refused is evidence, and a client that springs a trap twice is
// refused by the reputation blocker on its next, ordinary request. Without it
// the test above would pass with reputation switched off.
func TestATrapStillRefusesTheClientEverywhere(t *testing.T) {
	const attacker = "192.0.2.40"
	detectionStore(t)
	t.Cleanup(func() { telemetry.ResetReputation(repid.For(detectingBuild, attacker)) })
	h := enforcedRoute("trap-route", Deception(DeceptionConfig{RouteID: "trap-route", HoneypotPaths: []string{"/wp-admin"}}))

	for range 2 {
		if code := sendAs(h, attacker, httptest.NewRequest(http.MethodGet, "/wp-admin", nil)); code == http.StatusOK {
			t.Fatal("the trap let the request through")
		}
	}
	if code := sendAs(h, attacker, httptest.NewRequest(http.MethodGet, "/", nil)); code != http.StatusForbidden {
		t.Fatalf("a client that sprang the trap twice got %d on an ordinary request, want 403", code)
	}
}
