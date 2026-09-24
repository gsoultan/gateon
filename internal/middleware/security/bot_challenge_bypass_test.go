// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	botSecret = "bot-challenge-test-secret"
	botUA     = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
	botPeer   = "203.0.113.20"
)

// botRoute is a route behind bot management with the JS challenge on; reached
// reports whether a request got to the origin.
func botRoute(t *testing.T) (http.Handler, *bool) {
	t.Helper()
	reached := false
	h := BotManagement(BotManagementConfig{
		Enabled: true, EnableJSChallenge: true, SecretKey: botSecret, ChallengeTimeoutSeconds: 3600,
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	return h, &reached
}

func botRequest(method, target, ua string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("User-Agent", ua)
	req.RemoteAddr = botPeer + ":5555"
	return req
}

func withChallengeCookie(req *http.Request, value string) *http.Request {
	req.AddCookie(&http.Cookie{Name: ChallengeCookieName, Value: value})
	return req
}

// redeem posts a seed to the challenge endpoint and returns the response.
func redeem(h http.Handler, seed, ua string) *httptest.ResponseRecorder {
	form := url.Values{"token": {seed}, "redirect": {"/account"}}
	req := httptest.NewRequest(http.MethodPost, "/_gateon/challenge", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", ua)
	req.RemoteAddr = botPeer + ":5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func passCookie(rec *httptest.ResponseRecorder) string {
	for _, c := range rec.Result().Cookies() {
		if c.Name == ChallengeCookieName {
			return c.Value
		}
	}
	return ""
}

// TestSeedIsNotAPassCookie is the one-request bypass. The seed the challenge
// page fetches used to be exactly the token the cookie check accepted, so a
// client could fetch it and send it straight back as the cookie, without the
// page, the JavaScript or the wait.
func TestSeedIsNotAPassCookie(t *testing.T) {
	h, reached := botRoute(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, botRequest(http.MethodGet, "/_gateon/seed", botUA))
	seed := rec.Body.String()
	if seed == "" {
		t.Fatal("the seed endpoint returned nothing")
	}
	h.ServeHTTP(httptest.NewRecorder(), withChallengeCookie(botRequest(http.MethodGet, "/account", botUA), seed))
	if *reached {
		t.Fatal("a client that fetched /_gateon/seed and sent it back as the cookie reached the origin")
	}
}

// TestFreshSeedCannotBeRedeemed posts a seed the moment it is issued. The page
// waits before submitting; a client that does not wait has not done even that.
func TestFreshSeedCannotBeRedeemed(t *testing.T) {
	h, _ := botRoute(t)
	rec := redeem(h, seedFor(botSecret, botUA, botPeer, time.Now()), botUA)
	if passCookie(rec) != "" {
		t.Fatal("a seed redeemed the instant it was issued was exchanged for a pass")
	}
}

// TestChallengeFlowStillAdmitsABrowser walks the flow a browser takes: an aged
// seed is exchanged for a pass, and the pass reaches the origin.
func TestChallengeFlowStillAdmitsABrowser(t *testing.T) {
	h, reached := botRoute(t)
	rec := redeem(h, seedFor(botSecret, botUA, botPeer, time.Now().Add(-3*time.Second)), botUA)
	pass := passCookie(rec)
	if rec.Code != http.StatusFound || pass == "" {
		t.Fatalf("redeeming an aged seed: status %d, pass %q; want 302 and a pass cookie", rec.Code, pass)
	}
	h.ServeHTTP(httptest.NewRecorder(), withChallengeCookie(botRequest(http.MethodGet, "/account", botUA), pass))
	if !*reached {
		t.Fatal("a browser holding the pass it was just issued was challenged again")
	}
}

// TestUserAgentDigitsCannotForgeALongLivedPass obtains a pass while sending a
// User-Agent that starts with digits, then moves the digits onto the issue
// time. With no separators in the MAC input the signature still verified, for
// an issue time far in the future -- a pass that never expires.
func TestUserAgentDigitsCannotForgeALongLivedPass(t *testing.T) {
	h, reached := botRoute(t)
	const pad = "0000000"
	rec := redeem(h, seedFor(botSecret, pad+botUA, botPeer, time.Now().Add(-3*time.Second)), pad+botUA)
	issued, sig, ok := strings.Cut(passCookie(rec), ".")
	if !ok {
		t.Fatalf("no pass issued for the digit-prefixed User-Agent (status %d)", rec.Code)
	}
	forged := issued + pad + "." + sig
	h.ServeHTTP(httptest.NewRecorder(), withChallengeCookie(botRequest(http.MethodGet, "/account", botUA), forged))
	if *reached {
		t.Fatal("a pass re-cut from a digit-prefixed User-Agent was accepted with a far-future issue time")
	}
}

// TestFutureDatedPassIsRefused keeps a correctly signed pass from outliving
// its lifetime by claiming an issue time ahead of the clock.
func TestFutureDatedPassIsRefused(t *testing.T) {
	h, reached := botRoute(t)
	future := passFor(botSecret, botUA, botPeer, time.Now().Add(time.Hour))
	h.ServeHTTP(httptest.NewRecorder(), withChallengeCookie(botRequest(http.MethodGet, "/account", botUA), future))
	if *reached {
		t.Fatal("a pass dated an hour ahead of the clock was accepted")
	}
}

// TestPassStaysBoundToItsClientAddress moves a character across the boundary
// between the User-Agent and the client IP. With the fields run together, a pass
// issued to User-Agent "…1" at 2.3.4.5 verified for User-Agent "…" at 12.3.4.5:
// a pass minted from one address was good from another.
func TestPassStaysBoundToItsClientAddress(t *testing.T) {
	h, reached := botRoute(t)
	const issuedTo, replayedFrom = "2.3.4.5", "12.3.4.5"

	form := url.Values{"token": {seedFor(botSecret, botUA+"1", issuedTo, time.Now().Add(-3*time.Second))}}
	req := httptest.NewRequest(http.MethodPost, "/_gateon/challenge", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", botUA+"1")
	req.RemoteAddr = issuedTo + ":5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	pass := passCookie(rec)
	if pass == "" {
		t.Fatalf("no pass issued to %s (status %d)", issuedTo, rec.Code)
	}

	replay := httptest.NewRequest(http.MethodGet, "/account", nil)
	replay.Header.Set("User-Agent", botUA)
	replay.RemoteAddr = replayedFrom + ":5555"
	h.ServeHTTP(httptest.NewRecorder(), withChallengeCookie(replay, pass))
	if *reached {
		t.Fatalf("a pass issued to %s was accepted from %s", issuedTo, replayedFrom)
	}
}
