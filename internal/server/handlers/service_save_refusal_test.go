// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/domain/service"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type nopInvalidator struct{}

func (nopInvalidator) InvalidateRoute(string)                      {}
func (nopInvalidator) InvalidateRoutes(func(*gateonv1.Route) bool) {}
func (nopInvalidator) InvalidateTLS()                              {}
func (nopInvalidator) InvalidateWAF()                              {}

// TestServiceSaveRefusalReachesTheOperator: a service the gateway would not
// carry out as written is refused at save (ADR 0047), and the dashboard shows
// why. Every save error used to be answered 500 "failed to save service", so a
// refusal would have read as a server fault with nothing to fix.
func TestServiceSaveRefusalReachesTheOperator(t *testing.T) {
	dir := t.TempDir()
	svcs := config.NewServiceRegistry(filepath.Join(dir, "services.json"))
	d := &Deps{ServiceService: service.NewService(svcs,
		config.NewRouteRegistry(filepath.Join(dir, "routes.json")), nopInvalidator{}, nil)}
	mux := http.NewServeMux()
	registerServiceHandlers(mux, nil, d)

	body := `{"id":"lc","name":"lc","loadBalancerPolicy":"leastConn",` +
		`"weightedTargets":[{"url":"http://a:80","weight":1},{"url":"http://b:80","weight":5}]}`
	req := httptest.NewRequest(http.MethodPut, "/v1/services", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey,
		&auth.Claims{ID: "a-1", Username: "admin", Role: auth.RoleAdmin}))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "ignores target weights") {
		t.Fatalf("status %d body %q, want 400 saying the policy ignores target weights", rr.Code, rr.Body)
	}
	if _, ok := svcs.Get(context.Background(), "lc"); ok {
		t.Fatal("the refused service was stored")
	}
}
