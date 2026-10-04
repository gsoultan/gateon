// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
	"github.com/gsoultan/gateon/internal/testutil"
	dto "github.com/prometheus/client_model/go"
)

// The block lookups ran QueryRow with no context on every request and every
// TCP accept. With Postgres frozen a new address waited past 120 s, and so did
// loopback, an address seen a minute before and every TCP connection; a 40 s
// table lock made every new client wait 38 s (2026-10-04 review, DP-N1). Each
// test below stands a database that never answers -- the way lib/pq waits on
// a stopped server, ignoring its context -- behind the lookups (ADR 0054).

const (
	lookupDeadline = 50 * time.Millisecond
	// deadlineMargin is what an answer may take past the deadline on a loaded
	// CI runner under -race.
	deadlineMargin = 450 * time.Millisecond
)

// storeWithLookupDeadline opens a fresh store whose block lookups wait at most
// lookupDeadline.
func storeWithLookupDeadline(t *testing.T) {
	t.Helper()
	t.Setenv(envBlockLookupTimeout, lookupDeadline.String())
	freshStore(t)
}

// hangLookups stands a database that never answers behind the block lookups
// of the store open now; the store's own keeps serving everything else.
func hangLookups(t *testing.T) *testutil.HangDB {
	t.Helper()
	h := testutil.NewHangDB(t)
	restore := SetBlockLookupDBForTest(h.DB)
	t.Cleanup(func() {
		h.Release()
		WaitBlockLookupsForTest()
		restore()
	})
	return h
}

// decidedWithin runs decide and fails t unless it answers within the lookup
// deadline and the margin.
func decidedWithin(t *testing.T, what string, decide func() bool) bool {
	t.Helper()
	return answeredWithin(t, what, lookupDeadline+deadlineMargin, decide)
}

// answeredWithin runs decide and fails t unless it answers within limit. A
// decide still waiting is freed by hangLookups' cleanup, which releases the
// database.
func answeredWithin(t *testing.T, what string, limit time.Duration, decide func() bool) bool {
	t.Helper()
	done := make(chan bool, 1)
	start := time.Now()
	go func() { done <- decide() }()
	select {
	case v := <-done:
		return v
	case <-time.After(limit):
		t.Fatalf("%s: still waiting %v, against a database that does not answer (lookup deadline %s)",
			what, time.Since(start), os.Getenv(envBlockLookupTimeout))
		return false
	}
}

func lookupErrors(kind, reason string) float64 {
	var m dto.Metric
	if err := MitigationLookupErrorsTotal.WithLabelValues(kind, reason).Write(&m); err != nil {
		panic(err)
	}
	return m.GetCounter().GetValue()
}

// A new address -- one the cache has no answer for -- is decided within the
// deadline, served (ADR 0043's failed lookup), counted as a timeout and not
// cached; and a second request for it does not ask the database again while
// the first query is still outstanding.
func TestANewAddressIsDecidedWithinTheDeadlineWhenTheDatabaseHangs(t *testing.T) {
	storeWithLookupDeadline(t)
	h := hangLookups(t)
	const ip = "198.51.100.101"
	before := lookupErrors(mitigationLookupIP, lookupReasonTimeout)
	if decidedWithin(t, "a new address", func() bool { return IsIPMitigatedContext(t.Context(), ip) }) {
		t.Fatal("refused: a lookup that did not finish must be decided as a failed one, served")
	}
	if got := lookupErrors(mitigationLookupIP, lookupReasonTimeout) - before; got != 1 {
		t.Fatalf("timeouts counted %v, want 1", got)
	}
	if _, cached := getStore().unmitigatedCache.Peek(ip); cached {
		t.Fatal("a lookup that timed out was cached as an answer")
	}
	decidedWithin(t, "the same address again", func() bool { return IsIPMitigated(ip) })
	if n := h.Queries(); n != 1 {
		t.Fatalf("%d queries for one address against a hung database, want 1", n)
	}
}

// An address seen before is never held at all while its answer is inside the
// stale window: it is served from the cache, and read again once in the
// background. This is the "previously seen address" that hung once its
// answer was a minute or two old.
func TestAKnownAddressIsServedAtOnceAndReadAgainOnceWhenTheDatabaseHangs(t *testing.T) {
	// A deadline far longer than the limit below: an answer within the limit
	// was not waited for at all.
	t.Setenv(envBlockLookupTimeout, "1m")
	freshStore(t)
	const ip = "198.51.100.102"
	if IsIPMitigated(ip) {
		t.Fatal("shunned before anything was written")
	}
	ageCachedAnswer(t, ip, 2)
	h := hangLookups(t)
	for range 20 {
		if answeredWithin(t, "a known address", time.Second, func() bool { return IsIPMitigated(ip) }) {
			t.Fatal("refused on a stale \"not shunned\"")
		}
	}
	select {
	case <-h.Started():
	case <-time.After(5 * time.Second):
		t.Fatal("the stale answer was never read again")
	}
	h.Release()
	WaitBlockLookupsForTest()
	if n := h.Queries(); n != 1 {
		t.Fatalf("20 requests on a stale answer made %d queries, want one refresh", n)
	}
	// The refresh left a fresh answer: the next requests ask nothing.
	for range 20 {
		IsIPMitigated(ip)
	}
	if n := h.Queries(); n != 1 {
		t.Fatalf("a refreshed answer was read again: %d queries", n)
	}
}

// Past the stale window an address is read before it is decided -- and that
// read is bounded by the deadline too.
func TestAnAddressGoneLongerThanTheStaleWindowWaitsNoLongerThanTheDeadline(t *testing.T) {
	storeWithLookupDeadline(t)
	const ip = "198.51.100.103"
	IsIPMitigated(ip)
	ageCachedAnswer(t, ip, staleAnswerEpochs+1)
	hangLookups(t)
	if decidedWithin(t, "an address back after the stale window", func() bool { return IsIPMitigated(ip) }) {
		t.Fatal("refused on a lookup that did not finish")
	}
}

// A block this node holds is enforced while the database hangs, without
// asking it: an address's shun, and a fingerprint's block -- which used to be
// read again on every request (dataplane F7), so a blocked client cost a
// database round trip per request and, with the database hung, hung.
func TestAKnownBlockIsEnforcedWithoutTheDatabaseWhileItHangs(t *testing.T) {
	storeWithLookupDeadline(t)
	const ip = "198.51.100.104"
	if err := MarkIPMitigated(ip, "operator block"); err != nil {
		t.Fatal(err)
	}
	key := repid.For("t13d1516h2_8daaf6152771_b0da82dd1658", "198.51.100.105")
	MarkUserMitigated(key, "JA4+", "test", "waf")
	h := hangLookups(t)
	for range 50 {
		if !decidedWithin(t, "a shunned address", func() bool { return IsIPMitigated(ip) }) {
			t.Fatal("a shun in the cache was not enforced while the database hung")
		}
		if !decidedWithin(t, "a blocked fingerprint", func() bool { return IsUserMitigatedContext(t.Context(), key) }) {
			t.Fatal("a fingerprint block in the cache was not enforced while the database hung")
		}
	}
	if n := h.Queries(); n != 0 {
		t.Fatalf("blocks held in the cache made %d queries; a cached block decides without the database", n)
	}
	// Past the window a block is read again, and a read that does not finish
	// keeps it.
	ageCachedAnswer(t, key, staleAnswerEpochs+1)
	if !decidedWithin(t, "a fingerprint block past the window", func() bool { return IsUserMitigated(key) }) {
		t.Fatal("a known fingerprint block was dropped by a lookup that did not finish")
	}
}

// Concurrent requests from one new address share one query: a slow database
// is not asked once per request.
func TestConcurrentRequestsForOneAddressMakeOneQuery(t *testing.T) {
	storeWithLookupDeadline(t)
	h := hangLookups(t)
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() { IsIPMitigatedContext(t.Context(), "198.51.100.106") })
	}
	if !waitWithin(&wg, lookupDeadline+deadlineMargin) {
		h.Release()
		wg.Wait()
		t.Fatalf("50 requests for one address were still waiting past the deadline, and made %d queries", h.Queries())
	}
	if n := h.Queries(); n != 1 {
		t.Fatalf("50 concurrent requests for one address made %d queries, want 1", n)
	}
}

// No more lookups are in flight than the bound, however many new addresses
// arrive at once; the rest are decided at once, without queuing, and counted.
func TestInFlightLookupsNeverExceedTheBound(t *testing.T) {
	storeWithLookupDeadline(t)
	h := hangLookups(t)
	bound := blockLookupSlots(config.CurrentTierDefaults())
	before := lookupErrors(mitigationLookupIP, lookupReasonSaturated)
	var wg sync.WaitGroup
	for i := range bound + 20 {
		wg.Go(func() { IsIPMitigatedContext(t.Context(), fmt.Sprintf("203.0.113.%d", i)) })
	}
	if !waitWithin(&wg, lookupDeadline+deadlineMargin) {
		h.Release()
		wg.Wait()
		t.Fatalf("%d new addresses were still waiting past the deadline; %d queries ran at once (bound %d)",
			bound+20, h.Peak(), bound)
	}
	if p := h.Peak(); p > int64(bound) {
		t.Fatalf("%d lookups in flight at once; the bound is %d", p, bound)
	}
	if n := h.Queries(); n != int64(bound) {
		t.Fatalf("%d queries started, want the bound, %d", n, bound)
	}
	if got := lookupErrors(mitigationLookupIP, lookupReasonSaturated) - before; got != 20 {
		t.Fatalf("saturated lookups counted %v, want 20", got)
	}
}

// A lookup that read the database before this node wrote a block must not
// leave its answer cached over the block: with the answer arriving late -- a
// slow database, or a refresh in the background -- "not shunned" would
// otherwise replace the shun just written, for up to two minutes.
func TestABlockWrittenDuringALookupIsNotOverwrittenByItsAnswer(t *testing.T) {
	storeWithLookupDeadline(t)
	const ip = "198.51.100.107"
	h := testutil.NewHangDB(t)
	restore := SetBlockLookupDBForTest(h.DB)
	t.Cleanup(restore)
	// Outstanding: the database has not answered.
	decidedWithin(t, "a new address", func() bool { return IsIPMitigated(ip) })
	if err := MarkIPMitigated(ip, "operator block"); err != nil {
		t.Fatal(err)
	}
	h.Release() // the late answer: no row
	WaitBlockLookupsForTest()
	restore()
	if !IsIPMitigated(ip) {
		t.Fatal("a late \"not shunned\" replaced a block written while it was outstanding")
	}
}

// The deadline is the tier's unless GATEON_BLOCK_LOOKUP_TIMEOUT names a
// positive duration; zero or garbage is not "no deadline".
func TestTheLookupDeadlineIsTheTiersUnlessOverridden(t *testing.T) {
	td := config.DefaultsFor(config.TierStandard)
	for env, want := range map[string]time.Duration{
		"":      td.BlockLookupTimeout,
		"0":     td.BlockLookupTimeout,
		"-1s":   td.BlockLookupTimeout,
		"soon":  td.BlockLookupTimeout,
		"150ms": 150 * time.Millisecond,
	} {
		t.Setenv(envBlockLookupTimeout, env)
		if got := blockLookupTimeout(td); got != want {
			t.Errorf("%s=%q: %v, want %v", envBlockLookupTimeout, env, got, want)
		}
	}
	for tier, want := range map[config.Tier]int{config.TierMinimal: 40, config.TierStandard: 200, config.TierEnterprise: 800} {
		if b := blockLookupSlots(config.DefaultsFor(tier)); b != want {
			t.Errorf("%s tier bound %d, want %d", tier, b, want)
		}
	}
}

// SetBlockLookupDBForTest without a store is a test that would pass for the
// wrong reason; it says so.
func TestSettingTheLookupDatabaseWithNoStorePanics(t *testing.T) {
	ClosePathStatsStore(context.Background())
	defer func() {
		if recover() == nil {
			t.Fatal("no panic with no store open")
		}
	}()
	SetBlockLookupDBForTest(nil)
}

// waitWithin waits for wg, up to d; it reports whether wg finished.
func waitWithin(wg *sync.WaitGroup, d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// The cache-only answers never ask the database: an address or a fingerprint
// key the cache has nothing for is "cannot say", with a database that would
// hang behind them, and says once a lookup has been made.
func TestTheCacheOnlyAnswersNeverAskTheDatabase(t *testing.T) {
	storeWithLookupDeadline(t)
	const ip = "198.51.100.108"
	key := repid.For("t13d1516h2_8daaf6152771_b0da82dd1658", "198.51.100.109")
	MarkUserMitigated(key, "JA4+", "test", "waf")
	h := hangLookups(t)
	if _, ok := IPMitigationFromCache(ip); ok {
		t.Fatal("an address never looked up was answered from the cache")
	}
	if blocked, ok := UserMitigationFromCache(key); !ok || !blocked {
		t.Fatalf("a fingerprint block in the cache: blocked %v, answered %v; want both", blocked, ok)
	}
	if _, ok := UserMitigationFromCache(repid.For("t13d1516h2_8daaf6152771_b0da82dd1658", "203.0.113.9")); ok {
		t.Fatal("a fingerprint key never looked up was answered from the cache")
	}
	if blocked, ok := UserMitigationFromCache("t13d1516h2_8daaf6152771_b0da82dd1658"); !ok || blocked {
		t.Fatal("a key with no network scope is never enforced, and needs no lookup to say so")
	}
	if n := h.Queries(); n != 0 {
		t.Fatalf("the cache-only answers made %d queries", n)
	}
	h.Release()
	IsIPMitigated(ip)
	if blocked, ok := IPMitigationFromCache(ip); !ok || blocked {
		t.Fatalf("after a lookup found no shun: blocked %v, answered %v", blocked, ok)
	}
}

// BlockLookupTimeout is the deadline the store's lookups run with -- what
// identity's per-request budget is measured in -- and zero with no store.
func TestBlockLookupTimeoutIsTheStoresDeadline(t *testing.T) {
	storeWithLookupDeadline(t)
	if got := BlockLookupTimeout(); got != lookupDeadline {
		t.Fatalf("BlockLookupTimeout() = %v, want %v", got, lookupDeadline)
	}
	ClosePathStatsStore(context.Background())
	if got := BlockLookupTimeout(); got != 0 {
		t.Fatalf("with no store: %v, want 0", got)
	}
}
