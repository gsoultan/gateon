// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package challenge

import (
	"net/http"
	"time"

	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// The challenge page talks to the gateway on the URL it was served for, never
// on a path of the gateway's own (ADR 0045).
//
// It used to fetch /_gateon/seed and post to /_gateon/challenge. Routing runs
// before middleware, so those requests reached the challenge only on a route
// whose rule happened to match them: on PathPrefix(`/app`) both were 404, the
// page could never finish, and every visitor was held on it. Answering at the
// page's own URL reaches the same route by construction, whatever its rule.
// The headers below mark the page's requests; bot management answers them
// itself and never forwards them.
const (
	// HeaderChallenge marks a request from the challenge page:
	// "answer" carries a solution, "check" asks whether the pass stuck.
	HeaderChallenge = "X-Gateon-Challenge"
	// HeaderChallengeID carries the challenge ID an answer is for.
	HeaderChallengeID = "X-Gateon-Challenge-ID"
	// HeaderChallengeNonce carries the nonce that does the work.
	HeaderChallengeNonce = "X-Gateon-Challenge-Nonce"

	challengeAnswer = "answer"
	challengeCheck  = "check"
)

// serveChallengeRequest answers the challenge page's own requests and reports
// whether it did. Anything else is left to the caller.
func serveChallengeRequest(cfg BotManagementConfig, clientIP string, w http.ResponseWriter, r *http.Request) bool {
	switch r.Header.Get(HeaderChallenge) {
	case challengeAnswer:
		handleAnswer(cfg, clientIP, w, r)
		return true
	case challengeCheck:
		handleCheck(cfg, clientIP, w, r)
		return true
	}
	return false
}

// handleAnswer exchanges a solved challenge for the pass cookie. 204 means
// the pass was set, 410 that the challenge outlived its lifetime (the page
// offers a new one), 403 that the answer is not one: forged, foreign, or
// short of the work.
func handleAnswer(cfg BotManagementConfig, clientIP string, w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	telemetry.ActiveUnverifiedClientsTotal.Dec()
	w.Header().Set("Cache-Control", "no-store")
	a := answer{
		id: r.Header.Get(HeaderChallengeID), nonce: r.Header.Get(HeaderChallengeNonce),
		ua: r.UserAgent(), ip: clientIP,
	}
	switch a.check(cfg.SecretKey, now) {
	case answerExpired:
		w.WriteHeader(http.StatusGone)
		return
	case answerRefused:
		recordBotThreat(r, cfg, clientIP, "challenge-fail", 60,
			"Failed JavaScript challenge submission", kind.SeverityHigh)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	telemetry.MiddlewareBotManagementTotal.WithLabelValues(cfg.RouteID, "challenge_solved").Inc()
	// The pass is a bypass credential for this middleware, so it gets the
	// same attributes as a session cookie. Secure comes from
	// request.IsSecure rather than r.TLS: behind a TLS-terminating proxy
	// r.TLS is nil, and the attribute would be dropped in exactly the
	// deployments where the token is most exposed.
	// #nosec G124 -- Secure is set from the resolved scheme just below;
	// gosec cannot see through the variable.
	http.SetCookie(w, &http.Cookie{
		Name:     ChallengeCookieName,
		Value:    passFor(cfg.SecretKey, r.UserAgent(), clientIP, now),
		Path:     "/",
		HttpOnly: true,
		Secure:   request.IsSecure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   cfg.ChallengeTimeoutSeconds,
	})
	w.WriteHeader(http.StatusNoContent)
}

// handleCheck tells the page whether the browser sent the pass back. The
// cookie is HttpOnly, so the script cannot look for itself, and a browser
// that refuses cookies would otherwise solve the challenge, reload, and be
// challenged again for ever.
func handleCheck(cfg BotManagementConfig, clientIP string, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if cookie, err := r.Cookie(ChallengeCookieName); err == nil &&
		verifyPass(cookie.Value, cfg.SecretKey, r.UserAgent(), clientIP, time.Now(), passLifetime(cfg)) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusForbidden)
}

// challengeMethod is the method the page's requests use: the challenged
// request's own, so that a route whose rule names a method still matches
// them, limited to the methods fetch() sends without ceremony.
func challengeMethod(method string) string {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return method
	}
	return http.MethodGet
}

func serveJSChallenge(w http.ResponseWriter, r *http.Request, id string) {
	writeChallengePage(w, http.StatusForbidden, pageData{
		ID:     id,
		Method: challengeMethod(r.Method),
		Bits:   challengeBits,
		Mode:   modeAnswer,
	})
}
