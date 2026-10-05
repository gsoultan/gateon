// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/router"
)

// TestRouteProblemsEndpointListsTheRoutesThatCannotServe is OPS-N4 at the
// API: no endpoint carried a route's build failure, so the dashboard could
// not mark a route that answers 503 or matches nothing. A viewer may read it,
// as it may read routes; an anonymous caller may not.
func TestRouteProblemsEndpointListsTheRoutesThatCannotServe(t *testing.T) {
	mux := http.NewServeMux()
	want := []router.RouteProblem{{RouteID: "r1", Route: "api", Kind: router.ProblemRefuses, Reason: `middleware "gone" does not exist`}}
	registerRouteHandlers(mux, &Deps{RouteProblems: func(context.Context) []router.RouteProblem { return want }})

	viewer := context.WithValue(context.Background(), middleware.UserContextKey,
		&auth.Claims{ID: "2", Username: "v", Role: auth.RoleViewer})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/routes/problems", nil).WithContext(viewer))
	if rec.Code != http.StatusOK {
		t.Fatalf("viewer: status %d, want 200: %s", rec.Code, rec.Body)
	}
	var got []router.RouteProblem
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got) != 1 || got[0] != want[0] {
		t.Fatalf("body = %s (%v), want %+v", rec.Body, err, want)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/routes/problems", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: status %d, want 401", rec.Code)
	}
}
