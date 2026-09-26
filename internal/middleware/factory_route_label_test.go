// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestBotManagementAttributesChallengesToItsRoute checks that the route label
// the router hands the factory reaches the bot-management middleware.
//
// The factory read it from cfg["_route_id"], a key nothing writes — Create
// stores the label under "route_id" — so every challenge and every bot threat
// was filed against an empty route, and the Security Hub could not say which
// route was under attack. The oidc and file-security factories read the same
// unwritten key.
func TestBotManagementAttributesChallengesToItsRoute(t *testing.T) {
	const route = "bot label route"
	f := NewFactory(nil, &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{}}, nil, nil, t.TempDir())
	mw, err := f.Create(&gateonv1.Middleware{
		Id:   "bot-attribution",
		Type: "bot_management",
		Config: map[string]string{
			"enabled":             "true",
			"enable_js_challenge": "true",
			"secret_key":          "route-label-test",
		},
	}, route)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	served := telemetry.MiddlewareBotManagementTotal.WithLabelValues(route, "challenge_served")
	before := counterValue(t, served)

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36")
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK && rec.Body.Len() == 0 {
		t.Fatal("the request reached the backend; no challenge was served, so this test proves nothing")
	}
	if got := counterValue(t, served) - before; got != 1 {
		t.Fatalf("challenge_served for route %q rose by %v, want 1: the challenge was attributed to a different route", route, got)
	}
}

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	return m.GetCounter().GetValue()
}
