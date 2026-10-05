// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
)

// TestTheWAFUpdateEndpointIsGone: POST /v1/waf/update ran an update that could
// only fail -- there is no rule source to update from since ADR 0004 -- and the
// dashboard button that called it was removed by ADR 0063. ADR 0064 removes the
// route. An administrator, who could reach it before, now gets 404 from the
// management mux, and no service method is called.
func TestTheWAFUpdateEndpointIsGone(t *testing.T) {
	mux := http.NewServeMux()
	// The embedded nil interface panics on any call, so a route still wired to
	// the service fails the test even if it answered 404 itself.
	registerGlobalHandlers(mux, struct{ GlobalAndAuthAPI }{}, &Deps{})

	req := httptest.NewRequest(http.MethodPost, "/v1/waf/update", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey,
		&auth.Claims{ID: "a-1", Username: "admin", Role: auth.RoleAdmin}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST /v1/waf/update = %d, want 404: %s", rec.Code, rec.Body.String())
	}
}
