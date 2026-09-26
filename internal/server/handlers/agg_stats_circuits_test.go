// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/domain/route"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/pkg/proxy"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type listedRoutes struct {
	route.Service
	routes []*gateonv1.Route
}

func (l listedRoutes) ListPaginated(context.Context, int32, int32, string, *config.RouteFilter) ([]*gateonv1.Route, int32) {
	return l.routes, int32(len(l.routes))
}

// TestAggStatsCountsRouteBreakersAsCircuits: the circuit tiles counted only
// backend targets here, while the realtime snapshot that overwrites them a
// second later reads the route breakers' gauge -- so an open route breaker
// appeared and vanished with each refresh. Both now count down targets and
// open route breakers as open circuits.
func TestAggStatsCountsRouteBreakersAsCircuits(t *testing.T) {
	// A breaker publishes all three of its states, 1 for the one it is in.
	for route, state := range map[string]string{"agg-open": "open", "agg-half": "half-open", "agg-closed": "closed"} {
		for _, s := range []string{"closed", "open", "half-open"} {
			v := 0.0
			if s == state {
				v = 1
			}
			telemetry.CircuitBreakerState.WithLabelValues(route, s).Set(v)
		}
		t.Cleanup(func() { telemetry.CircuitBreakerState.DeletePartialMatch(prometheus.Labels{"route": route}) })
	}
	d := &Deps{
		RouteService: listedRoutes{routes: []*gateonv1.Route{{Id: "rt1"}, {Id: "rt2"}}},
		RouteStatsProvider: func(id string) []proxy.TargetStats {
			if id == "rt1" {
				return []proxy.TargetStats{{URL: "http://a", Alive: true}, {URL: "http://b"}}
			}
			return []proxy.TargetStats{{URL: "http://c", Alive: true}}
		},
	}
	mux := http.NewServeMux()
	registerDiagnosticHandlers(mux, nil, d)
	req := httptest.NewRequest(http.MethodGet, "/v1/diag/agg-stats", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey,
		&auth.Claims{Role: auth.RoleAdmin}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("agg-stats answered %d: %s", rec.Code, rec.Body)
	}
	var got map[string]float64
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := map[string]float64{
		"healthy_targets": 2, "total_targets": 3,
		"open_circuits":      2, // one down target, one open route breaker
		"half_open_circuits": 1,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}
