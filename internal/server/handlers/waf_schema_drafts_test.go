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
	"github.com/gsoultan/gateon/internal/security/waf/schemalearn"
)

func schemaDraftsMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/waf/schema-drafts", serveWAFSchemaDrafts)
	mux.HandleFunc("DELETE /v1/waf/schema-drafts/{route}", forgetWAFSchemaDraft)
	return mux
}

func asCaller(t *testing.T, method, target string, claims *auth.Claims) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	if claims != nil {
		req = req.WithContext(context.WithValue(t.Context(), middleware.UserContextKey, claims))
	}
	rec := httptest.NewRecorder()
	schemaDraftsMux().ServeHTTP(rec, req)
	return rec
}

// A viewer may read a draft, which holds no client's value, and may not
// discard one. Nobody unauthenticated may do either.
func TestWAFSchemaDraftsAreReadByViewersAndDiscardedByEditors(t *testing.T) {
	h := schemalearn.Shared().For("handler-drafts")
	for range 30 {
		h.Observe("GET", "/probe", "n=1")
	}
	viewer := &auth.Claims{ID: "2", Username: "viewer", Role: auth.RoleViewer}
	admin := &auth.Claims{ID: "1", Username: "admin", Role: auth.RoleAdmin}

	if rec := asCaller(t, http.MethodGet, "/v1/waf/schema-drafts", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("no caller read the drafts: %d", rec.Code)
	}
	if rec := asCaller(t, http.MethodDelete, "/v1/waf/schema-drafts/handler-drafts", viewer); rec.Code != http.StatusForbidden {
		t.Errorf("a viewer discarded a draft: %d", rec.Code)
	}

	read := func() schemalearn.Draft {
		rec := asCaller(t, http.MethodGet, "/v1/waf/schema-drafts", viewer)
		if rec.Code != http.StatusOK {
			t.Fatalf("a viewer could not read the drafts: %d %s", rec.Code, rec.Body.String())
		}
		var body struct {
			Drafts    []schemalearn.Draft `json:"drafts"`
			MaxRoutes int                 `json:"maxRoutes"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.MaxRoutes != schemalearn.MaxRoutes {
			t.Errorf("maxRoutes %d", body.MaxRoutes)
		}
		for _, d := range body.Drafts {
			if d.Route == "handler-drafts" {
				return d
			}
		}
		t.Fatalf("the route is not in %s", rec.Body.String())
		return schemalearn.Draft{}
	}
	if d := read(); d.Observed != 30 || d.Operations != 1 || d.Document == "" {
		t.Errorf("draft %+v", d)
	}

	if rec := asCaller(t, http.MethodDelete, "/v1/waf/schema-drafts/handler-drafts", admin); rec.Code != http.StatusNoContent {
		t.Errorf("an admin could not discard the draft: %d %s", rec.Code, rec.Body.String())
	}
	if d := read(); d.Observed != 0 || d.Document != "" {
		t.Errorf("after the discard: %+v", d)
	}
	if rec := asCaller(t, http.MethodDelete, "/v1/waf/schema-drafts/no-such-route", admin); rec.Code != http.StatusNotFound {
		t.Errorf("discarding a route that is not learning answered %d", rec.Code)
	}
}
