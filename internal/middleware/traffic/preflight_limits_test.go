// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"golang.org/x/time/rate"
)

// preflightReq builds the shape kind.IsCorsPreflight recognises. All three
// values are written by the client, which is why keying a limit off it means
// the caller decides whether the limit applies.
func preflightReq(method, body string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, "/api/items", nil)
	} else {
		r = httptest.NewRequest(method, "/api/items", strings.NewReader(body))
	}
	r.RemoteAddr = "203.0.113.44:5555"
	r.Header.Set("Origin", "https://evil.example")
	r.Header.Set("Access-Control-Request-Method", "POST")
	return r
}

// TestBodyLimitAppliesToAPreflightShapedRequest: OPTIONS may carry a body like
// any other method, and exemptFromBodyLimit waved one through for the price of
// two headers -- while its own comment said a protocol upgrade was the only
// exemption.
func TestBodyLimitAppliesToAPreflightShapedRequest(t *testing.T) {
	const limit = 64

	var readErr error
	h := MaxBodySize(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, preflightReq(http.MethodOptions, strings.Repeat("A", limit*4)))

	if readErr == nil {
		t.Errorf("a %d-byte body arrived intact under a %d-byte limit; naming a "+
			"preflight lifted the cap", limit*4, limit)
	}
}

// TestBodyLimitStillAllowsARealPreflight is the positive control. A genuine
// preflight carries no body, so a limit on bodies cannot affect it -- which is
// exactly why exempting it bought nothing.
func TestBodyLimitStillAllowsARealPreflight(t *testing.T) {
	var reached bool
	h := MaxBodySize(64)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	}))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, preflightReq(http.MethodOptions, ""))

	if !reached || rr.Code != http.StatusNoContent {
		t.Errorf("a bodyless preflight was refused: reached=%v status=%d", reached, rr.Code)
	}
}

// TestRateLimitAppliesToPreflightShapedRequests: a rate limit a caller steps
// out of by adding two headers is not a rate limit.
func TestRateLimitAppliesToPreflightShapedRequests(t *testing.T) {
	// A burst of one and effectively no refill. The effective burst is not
	// exactly one: getLimiter scales it by reputation/50, and an unrecorded
	// client's neutral reputation is 100, so the configured burst is doubled.
	// The test does not encode that -- it sends enough requests that any
	// plausible multiple is exhausted, and asserts one of them is refused.
	// Against the exemption all of them are served, however many are sent.
	rl := NewRateLimiter(rate.Limit(0.01), 1)
	defer rl.Close()

	h := rl.Handler(PerIP)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	const attempts = 8
	served, refused := 0, 0
	for range attempts {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, preflightReq(http.MethodOptions, ""))
		if rr.Code == http.StatusOK {
			served++
		} else {
			refused++
		}
	}

	if served == 0 {
		t.Fatalf("all %d preflights were refused; the limiter is not handing "+
			"out its burst at all", attempts)
	}
	if refused == 0 {
		t.Errorf("all %d preflights were served under a burst of one; the rate "+
			"limit is opt-out by writing an Origin and an "+
			"Access-Control-Request-Method", attempts)
	}
}

// TestPerIPConnectionLimitAppliesToPreflightShapedRequests holds the first
// request inside the handler so the second arrives while the single permit is
// taken. No sleep: the release is driven by the test.
func TestPerIPConnectionLimitAppliesToPreflightShapedRequests(t *testing.T) {
	inHandler := make(chan struct{})
	release := make(chan struct{})

	h := MaxConnectionsPerIP(1, PerIP)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case inHandler <- struct{}{}:
			<-release
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.ServeHTTP(httptest.NewRecorder(), preflightReq(http.MethodOptions, ""))
	}()

	<-inHandler // the permit is now held

	second := httptest.NewRecorder()
	h.ServeHTTP(second, preflightReq(http.MethodOptions, ""))

	close(release)
	wg.Wait()

	if second.Code == http.StatusOK {
		t.Error("a second concurrent preflight from the same address was served " +
			"while the only permit was held; the connection limit is opt-out")
	}
}
