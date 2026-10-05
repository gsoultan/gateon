// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package challenge

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// DP-N5. A proof-of-work pass was signed over the client's address and
// User-Agent only, under the route's secret -- and every route without a
// secret shares one generated process key. So a pass earned on a route asking
// for one hex zero admitted the client to a route asking for six, and a pass
// earned before an operator raised a route's difficulty still admitted at the
// new one. The pass and the challenge ID are now bound to the route and the
// difficulty they were earned at.

func powRoute(difficulty int, secret, routeID string) http.Handler {
	return Pow(difficulty, powTestThreshold, secret, routeID)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

// earnPass solves h's challenge at difficulty and returns the pass it hands out.
func earnPass(t *testing.T, h http.Handler, difficulty int) *http.Cookie {
	t.Helper()
	id := issueChallenge(t, h)
	nonce, sol := solvePoW(t, id, difficulty)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, powRequest(id, nonce, sol))
	if rec.Code != http.StatusOK {
		t.Fatalf("the route refused its own solved challenge: %d", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == PowPassCookieName {
			return c
		}
	}
	t.Fatal("a solved challenge handed out no pass")
	return nil
}

func statusWithPass(h http.Handler, pass *http.Cookie) int {
	req := powRequest("", "", "")
	req.AddCookie(pass)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestPowPassIsBoundToRouteAndDifficulty(t *testing.T) {
	for _, secret := range []string{"", "shared-operator-secret"} {
		t.Run("secret="+secret, func(t *testing.T) {
			pass := earnPass(t, powRoute(1, secret, "route-a"), 1)

			if got := statusWithPass(powRoute(1, secret, "route-a"), pass); got != http.StatusOK {
				t.Fatalf("control: the pass did not admit on the route that issued it (%d)", got)
			}
			if got := statusWithPass(powRoute(6, secret, "route-b"), pass); got == http.StatusOK {
				t.Error("a pass earned at difficulty 1 on route-a admitted on route-b at difficulty 6")
			}
			if got := statusWithPass(powRoute(1, secret, "route-b"), pass); got == http.StatusOK {
				t.Error("a pass earned on route-a admitted on route-b")
			}
			if got := statusWithPass(powRoute(6, secret, "route-a"), pass); got == http.StatusOK {
				t.Error("a pass earned at difficulty 1 still admitted after route-a moved to difficulty 6")
			}
		})
	}
}

// TestPowChallengeIsBoundToRoute: a challenge ID issued by one route is not an
// answerable challenge on another, even at the same difficulty under the same
// key.
func TestPowChallengeIsBoundToRoute(t *testing.T) {
	id := issueChallenge(t, powRoute(1, "", "route-a"))
	nonce, sol := solvePoW(t, id, 1)

	rec := httptest.NewRecorder()
	powRoute(1, "", "route-b").ServeHTTP(rec, powRequest(id, nonce, sol))
	if rec.Code == http.StatusOK {
		t.Fatal("a challenge issued and solved on route-a was accepted by route-b")
	}
}
