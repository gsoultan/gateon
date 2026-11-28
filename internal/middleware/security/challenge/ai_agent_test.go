// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package challenge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/security/aiagent"
	"github.com/gsoultan/gateon/internal/telemetry"
)

const gptbotUA = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot"

// openAIRanges is a store with GPTBot's list loaded from a vendor that
// publishes 192.0.2.0/24.
func openAIRanges(t *testing.T) *aiagent.Store {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"}]}`))
	}))
	t.Cleanup(srv.Close)
	s := aiagent.New(100, http.DefaultTransport)
	s.Configure([]aiagent.Source{{Agent: "GPTBot", URL: srv.URL}})
	s.Refresh(t.Context())
	return s
}

// aiRoute is a route that serves the JS challenge to everyone without a pass,
// as a route that protects its pages from scrapers does.
func aiRoute(policy AIAgentPolicy, ranges *aiagent.Store) http.Handler {
	return BotManagement(BotManagementConfig{
		Enabled:                 true,
		EnableJSChallenge:       true,
		ChallengeTimeoutSeconds: 3600,
		SecretKey:               "ai-agent-test-secret",
		RouteID:                 "ai-agent-route",
		AIAgents:                policy,
		AIAgentRanges:           ranges,
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("origin")) }))
}

// head is the start of a body, enough to tell a page from a challenge.
func head(rr *httptest.ResponseRecorder) string {
	b := rr.Body.String()
	return b[:min(len(b), 40)]
}

func crawl(h http.Handler, addr, ua string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/articles/1", nil)
	req.RemoteAddr = addr + ":40000"
	req.Header.Set("User-Agent", ua)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// TestAVerifyingRouteTellsTheRealCrawlerFromTheFake is ADR 0108. A route
// that challenges every client refuses the real GPTBot, which cannot run the
// challenge, along with the scraper that copied its User-Agent; one that
// waves the token through admits the scraper along with the crawler. With
// the vendor's list in force, the address decides.
func TestAVerifyingRouteTellsTheRealCrawlerFromTheFake(t *testing.T) {
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "ai-agent.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	defer telemetry.ClosePathStatsStore(context.Background())
	h := aiRoute(AIAgentsVerify, openAIRanges(t))

	if rr := crawl(h, "192.0.2.40", gptbotUA); rr.Code != http.StatusOK || rr.Body.String() != "origin" {
		t.Fatalf("the real GPTBot got %d %q, want the origin's page", rr.Code, head(rr))
	}

	const fake = "198.51.100.44"
	rr := crawl(h, fake, gptbotUA)
	if rr.Code != http.StatusForbidden || rr.Body.String() != kind.RefusalBody {
		t.Fatalf("a scraper naming GPTBot got %d %q, want the uniform refusal", rr.Code, head(rr))
	}
	telemetry.FlushThreats()
	if got := telemetry.CountSecurityThreats(t.Context(), &telemetry.ThreatFilter{Search: fake}); got != 1 {
		t.Fatalf("recorded %d threats for the fake, want 1", got)
	}

	// A claim no list can judge, and a client that makes none, meet the
	// route's challenge as before.
	for _, ua := range []string{"Mozilla/5.0 (compatible; ClaudeBot/1.0)", "curl/8.5.0"} {
		if rr := crawl(h, "192.0.2.40", ua); rr.Body.String() == "origin" {
			t.Errorf("%q reached the origin without the challenge", ua)
		}
	}
}

func TestARefusingRouteRefusesEveryAgentRealOrNot(t *testing.T) {
	h := aiRoute(AIAgentsRefuse, openAIRanges(t))
	rr := crawl(h, "192.0.2.40", gptbotUA)
	if rr.Code != http.StatusForbidden || rr.Body.String() != kind.RefusalBody {
		t.Fatalf("the real GPTBot got %d %q on a route that refuses AI agents", rr.Code, head(rr))
	}
}

func TestARouteWithNoPolicyIsUnchanged(t *testing.T) {
	h := aiRoute(AIAgentsOff, openAIRanges(t))
	if rr := crawl(h, "192.0.2.40", gptbotUA); rr.Body.String() == "origin" {
		t.Fatal("a route with no AI agent policy let a crawler past its challenge")
	}
}

func TestTheRoutesSettingIsReadStrictly(t *testing.T) {
	mw, err := NewBotManagement(map[string]string{AIAgentsKey: "verify"}, nil)
	if err != nil || mw == nil {
		t.Fatalf("ai_agents=verify refused: %v", err)
	}
	if _, err := NewBotManagement(map[string]string{AIAgentsKey: "Verify"}, nil); err == nil {
		t.Fatal(`ai_agents="Verify" was accepted; a typo must not silently mean off`)
	}
}

// TestAMazeRouteAnswersTheFakeWithAPageThatIsNotTheOrigins is ADR 0109: on
// a maze route, a client that names GPTBot from an address OpenAI does not
// publish gets a maze page, never the origin's, and the real crawler is
// unaffected.
func TestAMazeRouteAnswersTheFakeWithAPageThatIsNotTheOrigins(t *testing.T) {
	h := aiRoute(AIAgentsMaze, openAIRanges(t))
	if rr := crawl(h, "192.0.2.40", gptbotUA); rr.Body.String() != "origin" {
		t.Fatalf("the real GPTBot got %d %q, want the origin's page", rr.Code, head(rr))
	}
	rr := crawl(h, "198.51.100.45", gptbotUA)
	if rr.Code != http.StatusOK || rr.Body.String() == "origin" || rr.Header().Get("X-Robots-Tag") == "" {
		t.Fatalf("a scraper naming GPTBot got %d %q, want a maze page", rr.Code, head(rr))
	}
}
