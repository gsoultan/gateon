// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// powTestThreshold sits above the neutral score every unknown client starts
// with, so the middleware challenges each request in these tests.
const powTestThreshold = 101.0

// testPowChallenge is a challenge issuer with a fixed key, for tests that
// exercise the challenge page directly.
func testPowChallenge() powChallenge {
	return powChallenge{key: []byte("test-key"), difficulty: 3}
}

// solvePoW does the work the challenge page's script does: find a nonce whose
// SHA-256 over id+nonce starts with `difficulty` zero hex digits.
func solvePoW(t *testing.T, id string, difficulty int) (nonce, solution string) {
	t.Helper()
	target := strings.Repeat("0", difficulty)
	for n := 0; n < 1<<24; n++ {
		nonce = strconv.Itoa(n)
		sum := sha256.Sum256([]byte(id + nonce))
		solution = hex.EncodeToString(sum[:])
		if strings.HasPrefix(solution, target) {
			return nonce, solution
		}
	}
	t.Fatal("no proof-of-work solution found")
	return "", ""
}

func newPowHandler(secret string) http.Handler {
	return Pow(1, powTestThreshold, secret, "route")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

// powRequest is a request from one fixed client; with a non-empty id it also
// carries a solution.
func powRequest(id, nonce, solution string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.RemoteAddr = "203.0.113.9:4444"
	if id != "" {
		req.Header.Set("X-Gateon-Pow-ID", id)
		req.Header.Set(PowNonceHeader, nonce)
		req.Header.Set(PowHeaderSolution, solution)
	}
	return req
}

// issueChallenge asks h for a challenge and returns the ID it was given.
func issueChallenge(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, powRequest("", "", ""))
	id := rec.Header().Get("X-Gateon-Pow-ID")
	if rec.Code != http.StatusTooManyRequests || id == "" {
		t.Fatalf("expected a challenge, got status %d with id %q", rec.Code, id)
	}
	return id
}

// TestPowRoundTrip pins the legitimate flow: a client that solves the
// challenge the server issued to it gets through.
func TestPowRoundTrip(t *testing.T) {
	h := newPowHandler("s3cret")
	id := issueChallenge(t, h)
	nonce, sol := solvePoW(t, id, 1)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, powRequest(id, nonce, sol))
	if rec.Code != http.StatusOK {
		t.Fatalf("a valid solution to the server's own challenge was rejected: %d %s", rec.Code, rec.Body.String())
	}
}

// TestPowRejectsClientMintedChallenge is the regression test for an unsigned
// challenge. verifyPoW recomputed the hash over whatever ID the client sent, so
// a bot could mint its own ID, solve it once offline and present it on every
// request. With the timestamp a year ahead, time.Since is negative and the
// five-minute expiry never trips either: one hash computation, valid forever,
// shareable across a whole botnet. The secret the router insists on before
// installing the middleware was never used.
func TestPowRejectsClientMintedChallenge(t *testing.T) {
	h := newPowHandler("s3cret")
	future := time.Now().Add(365 * 24 * time.Hour).Unix()
	id := fmt.Sprintf("%d-%s-%s", future, strings.Repeat("0", 16), "salt")
	nonce, sol := solvePoW(t, id, 1)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, powRequest(id, nonce, sol))
	if rec.Code == http.StatusOK {
		t.Fatalf("a challenge the server never issued was accepted")
	}
}

// TestPowRejectsChallengeSignedByAnotherSecret: a challenge is only valid on
// the route whose secret issued it.
func TestPowRejectsChallengeSignedByAnotherSecret(t *testing.T) {
	id := issueChallenge(t, newPowHandler("other-secret"))
	nonce, sol := solvePoW(t, id, 1)

	rec := httptest.NewRecorder()
	newPowHandler("s3cret").ServeHTTP(rec, powRequest(id, nonce, sol))
	if rec.Code == http.StatusOK {
		t.Fatalf("a challenge issued under a different secret was accepted")
	}
}

// TestPowRejectsChallengeIssuedToAnotherClient: the ID embeds the requesting
// client's hashed reputation identity, and verification recomputes it for the
// presenting client, so one solved challenge cannot be handed around.
func TestPowRejectsChallengeIssuedToAnotherClient(t *testing.T) {
	h := newPowHandler("s3cret")
	id := issueChallenge(t, h)
	nonce, sol := solvePoW(t, id, 1)

	req := powRequest(id, nonce, sol)
	req.RemoteAddr = "198.51.100.7:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("a challenge issued to 203.0.113.9 was accepted from 198.51.100.7")
	}
}
