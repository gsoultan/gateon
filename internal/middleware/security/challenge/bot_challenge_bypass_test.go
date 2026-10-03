// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package challenge

import (
	"net/http"
	"net/http/httptest"
	"strconv"
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
// counts the requests that got to the origin.
func botRoute(t *testing.T) (http.Handler, *int) {
	t.Helper()
	reached := 0
	h := BotManagement(BotManagementConfig{
		Enabled: true, EnableJSChallenge: true, SecretKey: botSecret, ChallengeTimeoutSeconds: 3600,
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached++
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

// solveAnswer does the page script's work in Go: the first nonce whose
// SHA-256 over id ":" nonce begins with challengeBits zero bits.
func solveAnswer(t *testing.T, id string) string {
	t.Helper()
	for n := 0; n < 1<<26; n++ {
		if nonce := strconv.Itoa(n); workDone(id, nonce, challengeBits) {
			return nonce
		}
	}
	t.Fatal("no answer found")
	return ""
}

// unsolvedNonce is a nonce that does not do the work for id, so a test that
// expects a refusal cannot pass by a 1-in-2^18 accident.
func unsolvedNonce(t *testing.T, id string) string {
	t.Helper()
	for n := 0; ; n++ {
		if nonce := strconv.Itoa(n); !workDone(id, nonce, challengeBits) {
			return nonce
		}
	}
}

// answerRequest is the page's answer: the challenged URL, marked, with the ID
// and nonce in headers.
func answerRequest(ua, peer, id, nonce string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.Header.Set("User-Agent", ua)
	req.RemoteAddr = peer + ":5555"
	req.Header.Set(HeaderChallenge, challengeAnswer)
	req.Header.Set(HeaderChallengeID, id)
	req.Header.Set(HeaderChallengeNonce, nonce)
	return req
}

// redeem answers a challenge issued to (ua, peer) and returns the response.
func redeem(t *testing.T, h http.Handler, ua, peer string) *httptest.ResponseRecorder {
	t.Helper()
	id := challengeFor(botSecret, ua, peer, time.Now())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, answerRequest(ua, peer, id, solveAnswer(t, id)))
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

// TestChallengeIDIsNotAPassCookie: the ID is in the page source, so holding
// it must prove nothing. Before ADR 0045 the seed the page fetched was the
// thing a client redeemed after a wait; the ID now in its place is redeemable
// only with the work.
func TestChallengeIDIsNotAPassCookie(t *testing.T) {
	h, reached := botRoute(t)
	id := challengeFor(botSecret, botUA, botPeer, time.Now().Add(-time.Minute))
	h.ServeHTTP(httptest.NewRecorder(), withChallengeCookie(botRequest(http.MethodGet, "/account", botUA), id))
	if *reached != 0 {
		t.Fatal("a client that sent the challenge ID from the page as its cookie reached the origin")
	}
}

// TestAnswerWithoutTheWorkIsRefused is the curl bypass: everything a client
// that does not run the script can send -- the ID it was handed with any
// nonce -- is refused, and no pass is set.
func TestAnswerWithoutTheWorkIsRefused(t *testing.T) {
	h, reached := botRoute(t)
	id := challengeFor(botSecret, botUA, botPeer, time.Now().Add(-3*time.Second))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, answerRequest(botUA, botPeer, id, unsolvedNonce(t, id)))
	if rec.Code != http.StatusForbidden || passCookie(rec) != "" || *reached != 0 {
		t.Fatalf("an answer that did not do the work: status %d, pass %q, reached origin %d times; "+
			"want 403, no pass, never", rec.Code, passCookie(rec), *reached)
	}
}

// TestChallengeFlowStillAdmitsABrowser walks the flow the page takes: the
// work earns a pass, the pass reaches the origin.
func TestChallengeFlowStillAdmitsABrowser(t *testing.T) {
	h, reached := botRoute(t)
	rec := redeem(t, h, botUA, botPeer)
	pass := passCookie(rec)
	if rec.Code != http.StatusNoContent || pass == "" {
		t.Fatalf("answering with the work: status %d, pass %q; want 204 and a pass cookie", rec.Code, pass)
	}
	if *reached != 0 {
		t.Fatal("the answer itself was forwarded to the origin")
	}
	h.ServeHTTP(httptest.NewRecorder(), withChallengeCookie(botRequest(http.MethodGet, "/account", botUA), pass))
	if *reached != 1 {
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
	rec := redeem(t, h, pad+botUA, botPeer)
	issued, sig, ok := strings.Cut(passCookie(rec), ".")
	if !ok {
		t.Fatalf("no pass issued for the digit-prefixed User-Agent (status %d)", rec.Code)
	}
	forged := issued + pad + "." + sig
	h.ServeHTTP(httptest.NewRecorder(), withChallengeCookie(botRequest(http.MethodGet, "/account", botUA), forged))
	if *reached != 0 {
		t.Fatal("a pass re-cut from a digit-prefixed User-Agent was accepted with a far-future issue time")
	}
}

// TestFutureDatedPassIsRefused keeps a correctly signed pass from outliving
// its lifetime by claiming an issue time ahead of the clock.
func TestFutureDatedPassIsRefused(t *testing.T) {
	h, reached := botRoute(t)
	future := passFor(botSecret, botUA, botPeer, time.Now().Add(time.Hour))
	h.ServeHTTP(httptest.NewRecorder(), withChallengeCookie(botRequest(http.MethodGet, "/account", botUA), future))
	if *reached != 0 {
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

	pass := passCookie(redeem(t, h, botUA+"1", issuedTo))
	if pass == "" {
		t.Fatalf("no pass issued to %s", issuedTo)
	}
	replay := httptest.NewRequest(http.MethodGet, "/account", nil)
	replay.Header.Set("User-Agent", botUA)
	replay.RemoteAddr = replayedFrom + ":5555"
	h.ServeHTTP(httptest.NewRecorder(), withChallengeCookie(replay, pass))
	if *reached != 0 {
		t.Fatalf("a pass issued to %s was accepted from %s", issuedTo, replayedFrom)
	}
}

// TestAnswerIsBoundToTheChallengedClient: work done for one address's
// challenge does not earn a pass at another.
func TestAnswerIsBoundToTheChallengedClient(t *testing.T) {
	h, _ := botRoute(t)
	id := challengeFor(botSecret, botUA, botPeer, time.Now())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, answerRequest(botUA, "198.51.100.30", id, solveAnswer(t, id)))
	if rec.Code != http.StatusForbidden || passCookie(rec) != "" {
		t.Fatalf("work for %s's challenge presented from 198.51.100.30: status %d, pass %q; want 403 and none",
			botPeer, rec.Code, passCookie(rec))
	}
}

// TestExpiredChallengeIsGoneAndNotAnAttack: a genuine challenge answered
// after its lifetime -- a tab left open -- is told so (410, which the page
// turns into "start a new one") rather than refused as a forgery.
func TestExpiredChallengeIsGoneAndNotAnAttack(t *testing.T) {
	h, _ := botRoute(t)
	id := challengeFor(botSecret, botUA, botPeer, time.Now().Add(-challengeLifetime-time.Minute))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, answerRequest(botUA, botPeer, id, solveAnswer(t, id)))
	if rec.Code != http.StatusGone || passCookie(rec) != "" {
		t.Fatalf("an expired challenge: status %d, pass %q; want 410 and no pass", rec.Code, passCookie(rec))
	}
}

// TestChallengeRequestsNeverReachTheOrigin: the page's own requests are
// answered by the middleware whatever they carry, so marking a request as
// one is not a way past it -- or past anything after it in the chain.
func TestChallengeRequestsNeverReachTheOrigin(t *testing.T) {
	h, reached := botRoute(t)
	pass := passCookie(redeem(t, h, botUA, botPeer))
	id := challengeFor(botSecret, botUA, botPeer, time.Now())

	for name, req := range map[string]*http.Request{
		"a correct answer":            answerRequest(botUA, botPeer, id, solveAnswer(t, id)),
		"a wrong answer":              answerRequest(botUA, botPeer, id, unsolvedNonce(t, id)),
		"a check":                     botRequest(http.MethodGet, "/account", botUA),
		"an answer carrying a pass":   withChallengeCookie(answerRequest(botUA, botPeer, id, "1"), pass),
		"a check carrying a pass":     withChallengeCookie(botRequest(http.MethodGet, "/account", botUA), pass),
		"an answer with no ID at all": answerRequest(botUA, botPeer, "", ""),
	} {
		if strings.Contains(name, "check") {
			req.Header.Set(HeaderChallenge, challengeCheck)
		}
		h.ServeHTTP(httptest.NewRecorder(), req)
		if *reached != 0 {
			t.Fatalf("%s was forwarded to the origin", name)
		}
	}
}

// TestCheckSaysWhetherThePassStuck: the cookie is HttpOnly, so the page asks.
func TestCheckSaysWhetherThePassStuck(t *testing.T) {
	h, _ := botRoute(t)
	pass := passCookie(redeem(t, h, botUA, botPeer))
	check := func(req *http.Request) int {
		req.Header.Set(HeaderChallenge, challengeCheck)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := check(botRequest(http.MethodGet, "/account", botUA)); got != http.StatusForbidden {
		t.Errorf("check without the pass: %d, want 403", got)
	}
	if got := check(withChallengeCookie(botRequest(http.MethodGet, "/account", botUA), pass)); got != http.StatusNoContent {
		t.Errorf("check with the pass: %d, want 204", got)
	}
}
