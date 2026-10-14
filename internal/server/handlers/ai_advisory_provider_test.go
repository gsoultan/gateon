// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// fakeClaude answers the Messages API with text, or with status when it is
// not 200, and records the last request body it was sent.
type fakeClaude struct {
	srv   *httptest.Server
	body  atomic.Value // string
	calls atomic.Int32
}

func newFakeClaude(t *testing.T, status int, text string) *fakeClaude {
	t.Helper()
	f := &fakeClaude{}
	f.body.Store("")
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		data, _ := io.ReadAll(r.Body)
		f.body.Store(string(data))
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func aiMux(t *testing.T, ai *gateonv1.AIConfig) *http.ServeMux {
	t.Helper()
	globals := config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))
	must(t, globals.Update(context.Background(), &gateonv1.GlobalConfig{Ai: ai}))
	mux := http.NewServeMux()
	registerAIAdvisoryHandlers(mux, advisoryAPI{globals: globals}, &Deps{})
	return mux
}

func postAs(t *testing.T, mux *http.ServeMux, role, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey,
		&auth.Claims{ID: "u-" + role, Username: role, Role: role}))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func claudeConfig(url string) *gateonv1.AIConfig {
	return &gateonv1.AIConfig{Enabled: true, Provider: "anthropic", Model: "claude-test", BaseUrl: url, ApiKey: "sk-ant-secret"}
}

// TestAnalyzeConfigIsNarratedByTheConfiguredProvider: with a provider
// configured, the summary is its answer and the engine names it, while the
// findings stay the local ones -- and they are what the provider was shown.
func TestAnalyzeConfigIsNarratedByTheConfiguredProvider(t *testing.T) {
	claude := newFakeClaude(t, http.StatusOK, "Turn on the WAF first.")
	rr := postAs(t, aiMux(t, claudeConfig(claude.srv.URL)), auth.RoleViewer, "/v1/AnalyzeConfig", `{}`)
	var resp aiAnalysisResponse
	must(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	if resp.Summary != "Turn on the WAF first." || resp.Engine != "anthropic:claude-test" || resp.Notice != "" {
		t.Fatalf("response = %+v", resp)
	}
	if len(resp.Insights) == 0 || !strings.Contains(claude.body.Load().(string), resp.Insights[0].Title) {
		t.Errorf("the provider was not shown the local findings: %s", claude.body.Load())
	}
}

// TestAnalyzeConfigFallsBackWhenTheProviderFails: a failing provider leaves
// the local summary in place, says why, and the reason names neither the key
// nor the address it was sent to.
func TestAnalyzeConfigFallsBackWhenTheProviderFails(t *testing.T) {
	claude := newFakeClaude(t, http.StatusUnauthorized, "")
	rr := postAs(t, aiMux(t, claudeConfig(claude.srv.URL)), auth.RoleViewer, "/v1/AnalyzeConfig", `{}`)
	var resp aiAnalysisResponse
	must(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	if rr.Code != http.StatusOK || resp.Engine != engineLocal || !strings.Contains(resp.Summary, "Smart Engine") {
		t.Fatalf("status %d, response %+v; want the local analysis", rr.Code, resp)
	}
	if !strings.Contains(resp.Notice, "refused the API key") {
		t.Errorf("notice = %q, want the reason", resp.Notice)
	}
	if strings.Contains(rr.Body.String(), "sk-ant-secret") || strings.Contains(rr.Body.String(), claude.srv.URL) {
		t.Errorf("response leaks the key or the provider address: %s", rr.Body)
	}
}

func TestAnalyzeConfigMakesNoCallWhenAIIsOff(t *testing.T) {
	claude := newFakeClaude(t, http.StatusOK, "x")
	off := claudeConfig(claude.srv.URL)
	off.Enabled = false
	rr := postAs(t, aiMux(t, off), auth.RoleViewer, "/v1/AnalyzeConfig", `{}`)
	var resp aiAnalysisResponse
	must(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	if claude.calls.Load() != 0 || resp.Engine != engineLocal || resp.Notice != "" {
		t.Errorf("calls %d, response %+v; want no call and the local analysis", claude.calls.Load(), resp)
	}
}

// TestAnalyzeLogsSendsLinesOnlyWhenShared: without share_log_lines the
// provider gets the local tally and not one log line.
func TestAnalyzeLogsSendsLinesOnlyWhenShared(t *testing.T) {
	line := `time=2026-10-04T10:00:00Z level=INFO msg="access log" method=GET path=/secret-customer-path status=200`
	body := `{"logs":[` + strconvQuote(line) + `]}`
	for _, share := range []bool{false, true} {
		claude := newFakeClaude(t, http.StatusOK, "Looks fine.")
		cfg := claudeConfig(claude.srv.URL)
		cfg.ShareLogLines = share
		rr := postAs(t, aiMux(t, cfg), auth.RoleViewer, "/v1/AnalyzeLogs", body)
		var resp aiLogAnalysisResponse
		must(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		if resp.Analysis != "Looks fine." || !strings.Contains(resp.Local, "Analyzed 1 log lines") {
			t.Fatalf("share=%v: response %+v", share, resp)
		}
		if sent := strings.Contains(claude.body.Load().(string), "secret-customer-path"); sent != share {
			t.Errorf("share=%v: the line was sent to the provider: %v", share, sent)
		}
	}
}

// TestProviderTestNeedsTheRightToChangeSettings: the test spends a call on
// the stored key, which a viewer may not do.
func TestProviderTestNeedsTheRightToChangeSettings(t *testing.T) {
	claude := newFakeClaude(t, http.StatusOK, "OK")
	mux := aiMux(t, claudeConfig(claude.srv.URL))
	if rr := postAs(t, mux, auth.RoleViewer, "/v1/ai-advisory/test", ""); rr.Code != http.StatusForbidden {
		t.Errorf("viewer: status %d, want 403", rr.Code)
	}
	if claude.calls.Load() != 0 {
		t.Fatalf("a refused test still called the provider")
	}
	rr := postAs(t, mux, auth.RoleAdmin, "/v1/ai-advisory/test", "")
	var resp aiTestResponse
	must(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	if !resp.OK || resp.Engine != "anthropic:claude-test" {
		t.Errorf("admin: response %+v", resp)
	}
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
