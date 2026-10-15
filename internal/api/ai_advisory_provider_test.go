// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

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

// advisoryService is an ApiService whose global settings carry ai. The
// analysis RPCs read nothing else it holds.
func advisoryService(t *testing.T, ai *gateonv1.AIConfig) *ApiService {
	t.Helper()
	globals := config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))
	must(t, globals.Update(context.Background(), &gateonv1.GlobalConfig{Ai: ai}))
	return &ApiService{Globals: globals}
}

func claudeConfig(url string) *gateonv1.AIConfig {
	return &gateonv1.AIConfig{Enabled: true, Provider: "anthropic", Model: "claude-test", BaseUrl: url, ApiKey: "sk-ant-secret"}
}

// TestAnalyzeConfigIsNarratedByTheConfiguredProvider: with a provider
// configured, the summary is its answer and the engine names it, while the
// findings stay the local ones -- and they are what the provider was shown.
func TestAnalyzeConfigIsNarratedByTheConfiguredProvider(t *testing.T) {
	claude := newFakeClaude(t, http.StatusOK, "Turn on the WAF first.")
	resp, err := advisoryService(t, claudeConfig(claude.srv.URL)).
		AnalyzeConfig(withRole(auth.RoleViewer), &gateonv1.AnalyzeConfigRequest{})
	must(t, err)
	if resp.GetSummary() != "Turn on the WAF first." || resp.GetEngine() != "anthropic:claude-test" || resp.GetNotice() != "" {
		t.Fatalf("response = %+v", resp)
	}
	if len(resp.GetInsights()) == 0 || !strings.Contains(claude.body.Load().(string), resp.GetInsights()[0].GetTitle()) {
		t.Errorf("the provider was not shown the local findings: %s", claude.body.Load())
	}
}

// TestAnalyzeConfigFallsBackWhenTheProviderFails: a failing provider leaves
// the local summary in place, says why, and the reason names neither the key
// nor the address it was sent to.
func TestAnalyzeConfigFallsBackWhenTheProviderFails(t *testing.T) {
	claude := newFakeClaude(t, http.StatusUnauthorized, "")
	resp, err := advisoryService(t, claudeConfig(claude.srv.URL)).
		AnalyzeConfig(withRole(auth.RoleViewer), &gateonv1.AnalyzeConfigRequest{})
	if err != nil || resp.GetEngine() != "local" || !strings.Contains(resp.GetSummary(), "Smart Engine") {
		t.Fatalf("err %v, response %+v; want the local analysis", err, resp)
	}
	if !strings.Contains(resp.GetNotice(), "refused the API key") {
		t.Errorf("notice = %q, want the reason", resp.GetNotice())
	}
	if text := resp.String(); strings.Contains(text, "sk-ant-secret") || strings.Contains(text, claude.srv.URL) {
		t.Errorf("response leaks the key or the provider address: %s", text)
	}
}

func TestAnalyzeConfigMakesNoCallWhenAIIsOff(t *testing.T) {
	claude := newFakeClaude(t, http.StatusOK, "x")
	off := claudeConfig(claude.srv.URL)
	off.Enabled = false
	resp, err := advisoryService(t, off).AnalyzeConfig(withRole(auth.RoleViewer), &gateonv1.AnalyzeConfigRequest{})
	must(t, err)
	if claude.calls.Load() != 0 || resp.GetEngine() != "local" || resp.GetNotice() != "" {
		t.Errorf("calls %d, response %+v; want no call and the local analysis", claude.calls.Load(), resp)
	}
}

// TestAnalyzeLogsSendsLinesOnlyWhenShared: without share_log_lines the
// provider gets the local tally and not one log line.
func TestAnalyzeLogsSendsLinesOnlyWhenShared(t *testing.T) {
	line := `time=2026-10-04T10:00:00Z level=INFO msg="access log" method=GET path=/secret-customer-path status=200`
	for _, share := range []bool{false, true} {
		claude := newFakeClaude(t, http.StatusOK, "Looks fine.")
		cfg := claudeConfig(claude.srv.URL)
		cfg.ShareLogLines = share
		resp, err := advisoryService(t, cfg).AnalyzeLogs(withRole(auth.RoleViewer), &gateonv1.AnalyzeLogsRequest{Logs: []string{line}})
		must(t, err)
		if resp.GetAnalysis() != "Looks fine." || !strings.Contains(resp.GetLocal(), "Analyzed 1 log lines") {
			t.Fatalf("share=%v: response %+v", share, resp)
		}
		if sent := strings.Contains(claude.body.Load().(string), "secret-customer-path"); sent != share {
			t.Errorf("share=%v: the line was sent to the provider: %v", share, sent)
		}
	}
}

func TestTestAIProviderNamesTheEngineThatAnswered(t *testing.T) {
	claude := newFakeClaude(t, http.StatusOK, "OK")
	resp, err := advisoryService(t, claudeConfig(claude.srv.URL)).
		TestAIProvider(withRole(auth.RoleAdmin), &gateonv1.TestAIProviderRequest{})
	must(t, err)
	if !resp.GetOk() || resp.GetEngine() != "anthropic:claude-test" {
		t.Errorf("response %+v", resp)
	}
}
