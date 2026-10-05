// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
)

// A POST refused 401 or 403 counted as a credential attempt whatever it
// carried (ADR 0029's residue). GraphQL, gRPC-Web and Connect clients poll
// with POST -- the dashboard's own calls are Connect -- so once a session
// expired, every poll was a "refused credential attempt" and the brute-force
// check shunned the tab's address. The gateway knows better when its own
// verification refused the token the request presented: the auth middlewares
// mark the request (request.RefusalToken), and a marked refusal is not an
// attempt. ADR 0031.

// refusedPost is a POST to path whose refusal the gateway marked why.
func refusedPost(path string, why request.Refusal, header map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rs := &request.RequestState{}
	req = req.WithContext(request.WithState(req.Context(), rs))
	request.MarkRefused(req, why)
	return req
}

func TestAnExpiredSessionConnectPollerIsNotBruteForce(t *testing.T) {
	initAnomalyTestStore(t)
	agg := newIsolatedAggregator()
	const ip = "198.51.100.90"
	poll := refusedPost("/gateon.v1.ApiService/GetMetricsSnapshot", request.RefusalToken, map[string]string{
		"Cookie": "gateon_session=expired", "Content-Type": "application/json", "Connect-Protocol-Version": "1",
	})
	answered(agg, ip, 24, http.StatusUnauthorized, poll) // four polls a minute for six minutes

	if recorded, shunned := bruteForceOutcome(t, agg, ip); recorded || shunned {
		t.Errorf("a dashboard tab whose session expired -- every Connect poll a POST the gateway's "+
			"session check refused 401 -- was reported as brute force (%v) or shunned (%v)", recorded, shunned)
	}
}

// The mark is written by the check that refused, not read off the request:
// a password-stuffing POST to the login form that adds a bearer header is
// refused by the password check, which marks it an authentication refusal
// (ADR 0059), and still counts.
func TestLoginStuffingWithABogusBearerIsStillBruteForce(t *testing.T) {
	initAnomalyTestStore(t)
	agg := newIsolatedAggregator()
	const ip = "198.51.100.91"
	guess := refusedPost("/v1/login", request.RefusalAuthentication, map[string]string{
		"Authorization": "Bearer x", "Content-Type": "application/json",
	})
	answered(agg, ip, 24, http.StatusUnauthorized, guess)

	if recorded, shunned := bruteForceOutcome(t, agg, ip); !recorded || !shunned {
		t.Errorf("credential stuffing against /v1/login carrying a bogus bearer header was not "+
			"reported (%v) and shunned (%v): a header must not exempt a password guess", recorded, shunned)
	}
}

// Residue: a backend's own 401 to a POST still counts. The gateway did not
// check the credential and cannot tell a login form's refusal from an API's
// refusal of an expired token it verified itself.
func TestABackendsOwnRefusalOfAPostStillCounts(t *testing.T) {
	agg := newIsolatedAggregator()
	const ip = "198.51.100.92"
	api := refusedPost("/api/orders", request.RefusalNone, map[string]string{"Authorization": "Bearer expired"})
	// Answered by the backend: the request crossed the route's service boundary.
	request.ServiceBoundary(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})).ServeHTTP(httptest.NewRecorder(), api)
	answered(agg, ip, 3, http.StatusUnauthorized, api)
	counted := -1.0
	for _, s := range agg.GetIPStats(0) {
		if s.IP == ip {
			counted = s.AuthFail
		}
	}
	if counted != 3 {
		t.Errorf("%v of 3 POSTs a backend refused 401 counted as refused attempts, want 3", counted)
	}
}

// A POST a gateway layer refused before the request reached its service -- the
// WAF, a trap, the geofence, bot management, deception, TLS binding -- checked
// no credential. Each counted as a refused login, so a user whose form posts
// the WAF kept refusing was reported and shunned as a password guesser.
// ADR 0059.
func TestAPostAGatewayLayerRefusedIsNotBruteForce(t *testing.T) {
	initAnomalyTestStore(t)
	agg := newIsolatedAggregator()
	const ip = "198.51.100.93"
	refused := refusedPost("/checkout", request.RefusalNone, map[string]string{"Content-Type": "application/json"})
	answered(agg, ip, 24, http.StatusForbidden, refused)

	if recorded, shunned := bruteForceOutcome(t, agg, ip); recorded || shunned {
		t.Errorf("24 POSTs a gateway layer refused 403 before any credential check were reported as "+
			"brute force (%v) or shunned (%v)", recorded, shunned)
	}
}
