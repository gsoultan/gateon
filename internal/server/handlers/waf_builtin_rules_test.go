// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/security/waf"
)

func getBuiltinRules(t *testing.T, query string, claims *auth.Claims) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	registerWafRuleHandlers(mux, &api.ApiService{})
	req := httptest.NewRequest(http.MethodGet, "/v1/waf/rules/builtin"+query, nil)
	if claims != nil {
		req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey, claims))
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// TestRESTListsBuiltinRulesForAViewer drives the route the dashboard calls. A
// viewer can read it, because knowing what the WAF checks is not a privilege
// worth withholding from someone who can already see what it blocked.
func TestRESTListsBuiltinRulesForAViewer(t *testing.T) {
	rr := getBuiltinRules(t, "?page=1&pageSize=10",
		&auth.Claims{ID: "v-1", Username: "viewer", Role: auth.RoleViewer})
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /v1/waf/rules/builtin: %d %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Rules []struct {
			ID     uint32 `json:"id"`
			Name   string `json:"name"`
			Source string `json:"source"`
		} `json:"rules"`
		Total      int      `json:"total"`
		Categories []string `json:"categories"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %s: %v", rr.Body.String(), err)
	}
	catalog := waf.RuleCatalog()
	if body.Total != len(catalog) || len(body.Rules) != 10 {
		t.Fatalf("second page of ten: %d rules, total %d, want 10 of %d", len(body.Rules), body.Total, len(catalog))
	}

	first := getBuiltinRules(t, "?page=0&pageSize=10",
		&auth.Claims{ID: "v-1", Username: "viewer", Role: auth.RoleViewer})
	var firstBody struct {
		Rules []struct {
			ID uint32 `json:"id"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &firstBody); err != nil || len(firstBody.Rules) != 10 {
		t.Fatalf("first page: %v %s", err, first.Body.String())
	}
	if firstBody.Rules[9].ID >= body.Rules[0].ID {
		t.Errorf("page 1 starts at %d, page 0 ended at %d: the pages overlap", body.Rules[0].ID, firstBody.Rules[9].ID)
	}
	for _, r := range body.Rules {
		if r.ID == 0 || r.Name == "" || r.Source == "" {
			t.Errorf("a listed rule is missing a field the page prints: %+v", r)
		}
	}
}

func TestRESTBuiltinRulesNeedASession(t *testing.T) {
	if rr := getBuiltinRules(t, "", nil); rr.Code == http.StatusOK {
		t.Fatalf("GET /v1/waf/rules/builtin without a session: %d", rr.Code)
	}
}

// TestBuiltinRulesHaveNoWriteRoute: the list is read-only because there is
// nothing to write to, and the way to keep that true is for no pattern to
// match. PUT and POST on the path must not fall through to the custom-rule
// handlers either.
func TestBuiltinRulesHaveNoWriteRoute(t *testing.T) {
	mux := http.NewServeMux()
	registerWafRuleHandlers(mux, &api.ApiService{})
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch} {
		req := httptest.NewRequest(method, "/v1/waf/rules/builtin", nil)
		if _, pattern := mux.Handler(req); pattern != "" {
			t.Errorf("%s /v1/waf/rules/builtin matches %q", method, pattern)
		}
	}
}
