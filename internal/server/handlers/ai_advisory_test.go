// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// advisoryRPCs answers the three advisory RPCs and counts the calls that
// reach it. The analysis itself is tested in internal/ai/advisory and
// internal/api; these tests hold the REST transport to the RPCs.
type advisoryRPCs struct {
	GlobalAndAuthAPI
	calls int
	logs  []string
}

func (a *advisoryRPCs) AnalyzeConfig(context.Context, *gateonv1.AnalyzeConfigRequest) (*gateonv1.AnalyzeConfigResponse, error) {
	a.calls++
	return &gateonv1.AnalyzeConfigResponse{Summary: "s", Engine: "local",
		Insights: []*gateonv1.AIInsight{{Title: "t", SuggestedConfig: "waf: {}"}}}, nil
}

func (a *advisoryRPCs) AnalyzeLogs(_ context.Context, req *gateonv1.AnalyzeLogsRequest) (*gateonv1.AnalyzeLogsResponse, error) {
	a.calls++
	a.logs = req.GetLogs()
	return &gateonv1.AnalyzeLogsResponse{Analysis: "a", Local: "l", Engine: "local"}, nil
}

func (a *advisoryRPCs) TestAIProvider(context.Context, *gateonv1.TestAIProviderRequest) (*gateonv1.TestAIProviderResponse, error) {
	a.calls++
	return &gateonv1.TestAIProviderResponse{Ok: true, Engine: "anthropic:m", Message: "The provider answered."}, nil
}

func postAs(t *testing.T, svc GlobalAndAuthAPI, role, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	registerAIAdvisoryHandlers(mux, svc)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey,
		&auth.Claims{ID: "u-" + role, Username: role, Role: role}))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// TestAdvisoryRESTServesTheRPCs: the REST endpoints return what the RPCs
// return, under the field names the dashboard reads.
func TestAdvisoryRESTServesTheRPCs(t *testing.T) {
	svc := &advisoryRPCs{}
	rr := postAs(t, svc, auth.RoleViewer, "/v1/AnalyzeConfig", `{"focus":"security"}`)
	var cfg map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &cfg); err != nil || rr.Code != http.StatusOK {
		t.Fatalf("AnalyzeConfig: %d %s", rr.Code, rr.Body)
	}
	insights, _ := cfg["insights"].([]any)
	first, _ := insights[0].(map[string]any)
	if cfg["summary"] != "s" || cfg["engine"] != "local" || first["suggestedConfig"] != "waf: {}" {
		t.Errorf("AnalyzeConfig body = %s", rr.Body)
	}

	rr = postAs(t, svc, auth.RoleViewer, "/v1/AnalyzeLogs", `{"logs":["a line"]}`)
	if !strings.Contains(rr.Body.String(), `"local":"l"`) || len(svc.logs) != 1 || svc.logs[0] != "a line" {
		t.Errorf("AnalyzeLogs: body %s, lines passed %q", rr.Body, svc.logs)
	}
}

// TestProviderTestNeedsTheRightToChangeSettings: the test spends a call on
// the stored key, which a viewer may not do.
func TestProviderTestNeedsTheRightToChangeSettings(t *testing.T) {
	svc := &advisoryRPCs{}
	if rr := postAs(t, svc, auth.RoleViewer, "/v1/ai-advisory/test", ""); rr.Code != http.StatusForbidden {
		t.Errorf("viewer: status %d, want 403", rr.Code)
	}
	if svc.calls != 0 {
		t.Fatalf("a refused test still reached the provider")
	}
	if rr := postAs(t, svc, auth.RoleAdmin, "/v1/ai-advisory/test", ""); !strings.Contains(rr.Body.String(), `"ok":true`) {
		t.Errorf("admin: %d %s", rr.Code, rr.Body)
	}
}
