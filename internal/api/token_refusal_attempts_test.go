// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// The per-IP detector read every POST refused 401 or 403 as a refused
// credential attempt, so a Connect or GraphQL client polling with an expired
// session -- the dashboard's own calls are Connect POSTs -- read as password
// guessing. The trace now records when the gateway's own verification refused
// the token the request presented (TraceRecord.Refusal), which the metrics
// middleware copies from the mark the refusing middleware wrote, and such a
// refusal is not an attempt. ADR 0031.

// recordRefusedPosts records n traces of POSTs to path from ip, answered 401,
// the way the metrics middleware records them, with the refusal the request
// state carried.
func recordRefusedPosts(ip, path string, n int, header map[string][]string, why request.Refusal) {
	start := time.Now().Add(-3 * time.Minute)
	for i := range n {
		telemetry.RecordTrace(fmt.Sprintf("%s-%s-%d", ip, path, i), "POST "+path, "rt-app", "svc-app", 4,
			start.Add(time.Duration(i)*5*time.Second), "401", path, ip, "", "",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", http.MethodPost, "", "app.example.com"+path, "", "",
			header, nil, "", 100, 0, 0, 0, 0, why)
	}
}

func TestAnExpiredSessionConnectPollerIsNotReportedAsBruteForce(t *testing.T) {
	openTraceStore(t)
	const ip = "203.0.113.40"
	connect := map[string][]string{"Cookie": {"gateon_session=expired"}, "Content-Type": {"application/json"}}
	for _, path := range []string{"/gateon.v1.ApiService/GetMetricsSnapshot", "/gateon.v1.ApiService/ListRoutes"} {
		recordRefusedPosts(ip, path, 36, connect, request.RefusalToken)
	}

	if found := findingsAbout(t, ip); len(found) > 0 {
		t.Errorf("a tab whose session expired, polling with Connect POSTs the gateway's session "+
			"check refused, was reported:%s", describe(found))
	}
}

// The mark comes from the check that refused. /v1/login is not behind the
// session check, so a stuffing POST that adds a bearer header is refused by
// the password check, marks nothing, and is still guessing.
func TestLoginStuffingWithABogusBearerIsReportedAsBruteForce(t *testing.T) {
	openTraceStore(t)
	const ip = "203.0.113.41"
	stuffing := map[string][]string{"Authorization": {"Bearer x"}, "Content-Type": {"application/json"}}
	recordRefusedPosts(ip, "/v1/login", 30, stuffing, request.RefusalNone)

	assertBruteForceReported(t, ip)
}

// Residue: a backend's own 401 to a POST is still counted. The gateway did not
// check the token, so it cannot tell an API refusing an expired one from a
// login form refusing a password.
func TestABackendsOwnRefusalOfAPostIsStillCounted(t *testing.T) {
	openTraceStore(t)
	const ip = "203.0.113.42"
	api := map[string][]string{"Authorization": {"Bearer expired"}, "Content-Type": {"application/json"}}
	recordRefusedPosts(ip, "/api/graphql", 30, api, request.RefusalNone)

	assertBruteForceReported(t, ip)
}
