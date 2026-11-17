// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/security/waf/corpus"
)

// The sample is request traffic. Only someone who may change the WAF rules
// may read it: not a viewer, and not a request nobody authenticated.
func TestWAFCorpusIsServedOnlyToWhoMayChangeTheRules(t *testing.T) {
	corpus.Shared().Add(&corpus.Entry{Name: "handler-test GET /probe", Method: "GET", Target: "/probe"})

	serve := func(claims *auth.Claims) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, corpus.Path, nil)
		if claims != nil {
			req = req.WithContext(context.WithValue(t.Context(), middleware.UserContextKey, claims))
		}
		rec := httptest.NewRecorder()
		serveWAFCorpus(rec, req)
		return rec
	}

	if rec := serve(nil); rec.Code != http.StatusUnauthorized || strings.Contains(rec.Body.String(), "/probe") {
		t.Errorf("no caller: status %d body %q", rec.Code, rec.Body.String())
	}
	viewer := serve(&auth.Claims{ID: "2", Username: "viewer", Role: auth.RoleViewer})
	if viewer.Code != http.StatusForbidden || strings.Contains(viewer.Body.String(), "/probe") {
		t.Errorf("a viewer: status %d body %q", viewer.Code, viewer.Body.String())
	}
	admin := serve(&auth.Claims{ID: "1", Username: "admin", Role: auth.RoleAdmin})
	if admin.Code != http.StatusOK || !strings.Contains(admin.Body.String(), `"target":"/probe"`) {
		t.Errorf("an admin: status %d body %q", admin.Code, admin.Body.String())
	}
	if ct := admin.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Errorf("content type %q", ct)
	}
}
