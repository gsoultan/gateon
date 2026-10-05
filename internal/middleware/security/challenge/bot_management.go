// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package challenge

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/telemetry"
)

type BotManagementConfig struct {
	Enabled                 bool
	EnableJSChallenge       bool
	EnableBrowserIntegrity  bool
	ChallengeTimeoutSeconds int
	SecretKey               string
	RouteID                 string
}

const (
	ChallengeCookieName = "gateon_bot_challenge"
)

// BotManagement returns the bot-management middleware: the browser header
// consistency check and the JavaScript proof-of-work challenge (ADR 0045).
//
// What a pass proves, and all it proves: a client at this address with this
// User-Agent ran the challenge script, or did its work some other way, within
// the pass lifetime. It raises the cost of automated requests; it does not
// prove a human.
func BotManagement(cfg BotManagementConfig) kind.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serveBotManagement(cfg, next, w, r)
		})
	}
}

func serveBotManagement(cfg BotManagementConfig, next http.Handler, w http.ResponseWriter, r *http.Request) {
	if !cfg.Enabled || kind.IsCorsPreflight(r) {
		next.ServeHTTP(w, r)
		return
	}

	clientIP := telemetry.ClientIPOf(r)

	// 1. Browser header consistency.
	if cfg.EnableBrowserIntegrity && !checkBrowserIntegrity(r) {
		logger.SecurityEvent("bot_detected_integrity", r, "failed browser integrity check")
		recordBotThreat(r, cfg, clientIP, "integrity", 40,
			"Failed browser integrity check (Sec-Fetch headers)", kind.SeverityMedium)
		http.Error(w, "Forbidden - Browser Integrity Check Failed", http.StatusForbidden)
		return
	}

	// 2. The challenge page's own requests. They are answered here, at the
	// challenge's place in the route's chain, and never reach the origin --
	// so every check before this one has already run on them, and none after
	// it is skipped for anything that reaches the backend.
	if cfg.EnableJSChallenge && serveChallengeRequest(cfg, clientIP, w, r) {
		return
	}

	// 3. A client that has passed.
	if cookie, err := r.Cookie(ChallengeCookieName); err == nil &&
		verifyPass(cookie.Value, cfg.SecretKey, r.UserAgent(), clientIP, time.Now(), passLifetime(cfg)) {
		next.ServeHTTP(w, r)
		return
	}

	// 4. Everyone else gets the challenge.
	if cfg.EnableJSChallenge {
		telemetry.MiddlewareBotManagementTotal.WithLabelValues(cfg.RouteID, "challenge_served").Inc()
		unverifiedClients.served()
		serveJSChallenge(w, r, challengeFor(cfg.SecretKey, r.UserAgent(), clientIP, time.Now()))
		return
	}

	next.ServeHTTP(w, r)
}

// recordBotThreat files one bot-management refusal for the dashboard.
func recordBotThreat(r *http.Request, cfg BotManagementConfig, clientIP, label string, score float64, details, severity string) {
	telemetry.RecordSecurityThreat(telemetry.RecordSecurityThreatWithJA4(r, telemetry.SecurityThreat{
		ID:          fmt.Sprintf("bot-%s-%s-%s", label, cfg.RouteID, clientIP),
		Type:        "bot_detected",
		SourceIP:    clientIP,
		Score:       score,
		Details:     details,
		Time:        time.Now(),
		RouteID:     cfg.RouteID,
		RequestURI:  r.URL.RequestURI(),
		Category:    "bot",
		Severity:    severity,
		ActionTaken: kind.ActionBlocked,
	}))
}

// modernBrowserTokens are the User-Agent product tokens of browsers that send
// Sec-Fetch-* metadata on every request: Chrome and Edge since 76/79, Firefox
// since 90, Safari since 16.4. Matched as the browsers write them, so the
// check allocates nothing; a client that writes them otherwise is not one of
// these browsers and is treated as making no claim.
var modernBrowserTokens = [...]string{"Chrome/", "Edg/", "Firefox/", "Safari/"}

// checkBrowserIntegrity is a consistency check, not a browser verification
// (ADR 0045). It refuses a request with no User-Agent, and a request whose
// User-Agent claims a modern browser but that carries none of the fetch
// metadata such a browser sends -- a script that copied a browser's
// User-Agent and nothing else. A client that does not claim to be a browser
// (curl, an SDK, a crawler) passes: refusing those is the JS challenge's job.
func checkBrowserIntegrity(r *http.Request) bool {
	ua := r.UserAgent()
	if ua == "" {
		return false
	}
	if !claimsModernBrowser(ua) {
		return true
	}
	return r.Header.Get("Sec-Fetch-Site") != "" ||
		r.Header.Get("Sec-Fetch-Mode") != "" ||
		r.Header.Get("Sec-Fetch-Dest") != ""
}

func claimsModernBrowser(ua string) bool {
	for _, token := range modernBrowserTokens {
		if strings.Contains(ua, token) {
			return true
		}
	}
	return false
}
