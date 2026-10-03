// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/testutil"
)

// With Postgres frozen, every request IPMitigation saw waited for the block
// list -- a new address, an address seen a minute before, and loopback, whose
// exemption was read only after the lookup -- for as long as Postgres stayed
// frozen (2026-10-04 review, DP-N1). Requests are now decided within the
// lookup deadline, and an exempt client never waits for the database at all
// (ADR 0054).

const lookupDeadline = 50 * time.Millisecond

// lookupDeadlineStore opens a store whose block lookups wait at most
// lookupDeadline.
func lookupDeadlineStore(t *testing.T) {
	t.Helper()
	t.Setenv("GATEON_BLOCK_LOOKUP_TIMEOUT", lookupDeadline.String())
	scopeTestStore(t)
}

// hangLookupDB stands a database that never answers behind the block lookups
// of the store open now.
func hangLookupDB(t *testing.T) *testutil.HangDB {
	t.Helper()
	h := testutil.NewHangDB(t)
	restore := telemetry.SetBlockLookupDBForTest(h.DB)
	t.Cleanup(func() {
		h.Release()
		telemetry.WaitBlockLookupsForTest()
		restore()
	})
	return h
}

// answeredWithin runs serve and fails t unless it answers within the lookup
// deadline and a margin for a loaded runner.
func answeredWithin(t *testing.T, what string, serve func() int) int {
	t.Helper()
	return answeredWithinLimit(t, what, lookupDeadline+450*time.Millisecond, serve)
}

func answeredWithinLimit(t *testing.T, what string, limit time.Duration, serve func() int) int {
	t.Helper()
	done := make(chan int, 1)
	start := time.Now()
	go func() { done <- serve() }()
	select {
	case code := <-done:
		return code
	case <-time.After(limit):
		t.Fatalf("%s: still waiting %v, against a database that does not answer (lookup deadline %s)",
			what, time.Since(start), os.Getenv("GATEON_BLOCK_LOOKUP_TIMEOUT"))
		return 0
	}
}

func TestARequestIsDecidedWithinTheLookupDeadlineWhenTheDatabaseHangs(t *testing.T) {
	const known = "198.51.100.150"
	lookupDeadlineStore(t)
	if code := ipMitigationStatus(known); code != http.StatusOK {
		t.Fatalf("setup: %s got %d", known, code)
	}
	hangLookupDB(t)
	for _, c := range []struct{ name, ip string }{
		{"a new address", "198.51.100.151"},
		{"a known address", known},
		{"loopback", "127.0.0.1"},
		{"IPv6 loopback", "::1"},
	} {
		if code := answeredWithin(t, c.name, func() int { return ipMitigationStatus(c.ip) }); code != http.StatusOK {
			t.Errorf("%s got %d; a lookup that did not finish is decided as a failed one, served", c.name, code)
		}
	}
}

// Loopback and the allowlist are decided before the block list is read, so
// an exempt client costs the database nothing and cannot wait for it -- on
// the address list and the fingerprint block alike.
func TestAnExemptClientNeverAsksTheDatabase(t *testing.T) {
	lookupDeadlineStore(t)
	h := hangLookupDB(t)
	const allowlisted = "203.0.113.200"
	withAllowlist(t, allowlisted+"/32")
	for _, ip := range []string{"127.0.0.1", "::1", allowlisted} {
		answeredWithin(t, "IPMitigation from "+ip, func() int { return ipMitigationStatus(ip) })
		answeredWithin(t, "UserMitigation from "+ip, func() int {
			code, _ := userMitigationStatus(chromeJA4Plus, ip)
			return code
		})
	}
	if n := h.Queries(); n != 0 {
		t.Fatalf("exempt clients made %d block-list queries, want none", n)
	}
	// Control: a client that is not exempt does ask.
	answeredWithin(t, "UserMitigation from a new client", func() int {
		code, _ := userMitigationStatus(chromeJA4Plus, "198.51.100.152")
		return code
	})
	if h.Queries() == 0 {
		t.Fatal("control: a client that is not exempt made no query; the test cannot see a lookup")
	}
}

// A request meets IPMitigation and UserMitigation twice -- at the entrypoint
// and again at the route. Each lookup waiting a deadline of its own, a new
// client waited one per lookup; the request's lookups share one deadline.
func TestARequestWaitsOneLookupDeadlineThroughTheWholeChain(t *testing.T) {
	const deadline = 250 * time.Millisecond
	t.Setenv("GATEON_BLOCK_LOOKUP_TIMEOUT", deadline.String())
	scopeTestStore(t)
	hangLookupDB(t)
	chain := IPMitigation()(UserMitigation()(IPMitigation()(UserMitigation()(okOrigin()))))
	code := answeredWithinLimit(t, "a new client through both passes", deadline+200*time.Millisecond, func() int {
		req := httptest.NewRequest(http.MethodGet, "/account", nil)
		req.RemoteAddr = net.JoinHostPort("198.51.100.160", "41000")
		req = req.WithContext(request.WithState(req.Context(), &request.RequestState{JA4Plus: chromeJA4Plus}))
		rr := httptest.NewRecorder()
		chain.ServeHTTP(rr, req)
		return rr.Code
	})
	if code != http.StatusOK {
		t.Fatalf("got %d; lookups that did not finish are decided as failed ones, served", code)
	}
}
