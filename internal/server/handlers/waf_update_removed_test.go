// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestTheWAFUpdateEndpointIsGone: POST /v1/waf/update ran an update that could
// only fail -- there is no rule source to update from since ADR 0004 -- and the
// dashboard button that called it was removed by ADR 0063. ADR 0064 removes the
// route: the management mux has no pattern for it, so it answers 404 without
// reaching any service method.
func TestTheWAFUpdateEndpointIsGone(t *testing.T) {
	mux := http.NewServeMux()
	registerGlobalHandlers(mux, struct{ GlobalAndAuthAPI }{}, &Deps{})

	req := httptest.NewRequest(http.MethodPost, "/v1/waf/update", nil)
	// Asked of the mux rather than served: the stand-in service is nil, and a
	// route still wired to it would dereference it.
	if _, pattern := mux.Handler(req); pattern != "" {
		t.Fatalf("POST /v1/waf/update still matches %q", pattern)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST /v1/waf/update = %d, want 404", rec.Code)
	}
}
