// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry/repid"
	"github.com/gsoultan/gateon/internal/testutil"
	dto "github.com/prometheus/client_model/go"
)

// The block lookups decide a request they cannot finish -- the gate
// saturated, the database slow or hung -- as served, unless this node's cache
// already holds the block (ADR 0043, 0054). The cache learns a block only by
// looking it up, so after a restart every block was unknown until it was
// looked up, and an attacker with many addresses could keep the lookups
// saturated. Every block in force is now read into a list at start-up and
// every minute, and enforced from it without a lookup (ADR 0058).

// onEachPreloadEngine runs test on SQLite and, with GATEON_TEST_POSTGRES_DSN
// set, on Postgres. test gets the database URL, so it can open the store on
// it again: a restart.
func onEachPreloadEngine(t *testing.T, test func(t *testing.T, url string)) {
	t.Run("sqlite", func(t *testing.T) {
		url := "sqlite://" + filepath.Join(t.TempDir(), "preload.db")
		openPreloadStore(t, url)
		test(t, url)
	})
	t.Run("postgres", func(t *testing.T) {
		url := testutil.PostgresDSN(t, "skipping the Postgres run")
		openPreloadStore(t, url)
		test(t, url)
	})
}

// openPreloadStore opens the store on url with both block tables empty, and
// leaves them empty when the test ends: a shared Postgres keeps rows.
func openPreloadStore(t *testing.T, url string) {
	t.Helper()
	t.Setenv("GATEON_TRACE_DIR", t.TempDir())
	t.Setenv(envBlockLookupTimeout, lookupDeadline.String())
	restartStore(t, url)
	emptyBlockTables(t)
	t.Cleanup(func() { emptyBlockTables(t) })
	resetAddressEvidence()
	t.Cleanup(resetAddressEvidence)
}

// restartStore closes the store and opens it again on url, as a restart does:
// nothing in memory survives, everything in the database does.
func restartStore(t *testing.T, url string) {
	t.Helper()
	_ = ClosePathStatsStore(context.Background())
	if err := InitPathStatsStore(url, 1); err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { _ = ClosePathStatsStore(context.Background()) })
}

func emptyBlockTables(t *testing.T) {
	t.Helper()
	if s := getStore(); s != nil {
		for _, table := range []string{"ip_mitigations", "user_mitigations"} {
			if _, err := s.db.Exec(`DELETE FROM ` + table); err != nil {
				t.Fatalf("empty %s: %v", table, err)
			}
		}
	}
}

// writtenBeforeTheRestart are blocks in force, of every kind, and two that are
// not: an automatic shun that lapsed and a fingerprint block released.
type writtenBeforeTheRestart struct {
	blockedIPs  []string
	blockedKeys []string
	lapsedIP    string
	releasedKey string
}

func writeBlocksBeforeARestart(t *testing.T) writtenBeforeTheRestart {
	t.Helper()
	w := writtenBeforeTheRestart{
		blockedIPs:  []string{"198.51.100.201", "198.51.100.202", "198.51.100.203", "2001:db8:77:1::5"},
		blockedKeys: []string{repid.For(scopeChrome, "203.0.113.20")},
		lapsedIP:    "198.51.100.204",
		releasedKey: repid.For(scopeChrome, "192.0.2.21"),
	}
	mustBlock(t, MarkIPMitigated(w.blockedIPs[0], "operator"))
	mustBlock(t, MarkIPMitigatedFor(w.blockedIPs[1], "operator, for an hour", time.Hour))
	if res, err := ShunAutomatically(w.blockedIPs[2], "test"); err != nil || res.Outcome != ShunApplied {
		t.Fatalf("automatic shun: %v, %v", res, err)
	}
	mustBlock(t, MarkIPMitigated(w.blockedIPs[3], "operator"))
	mustBlock(t, MarkIPMitigatedFor(w.lapsedIP, "operator, for an hour", time.Hour))
	ageIPShun(t, w.lapsedIP, 2*time.Hour)
	MarkUserMitigated(w.blockedKeys[0], "JA4+", "test", "waf")
	MarkUserMitigated(w.releasedKey, "JA4+", "test", "waf")
	MarkUserUnmitigated(w.releasedKey)
	return w
}

func mustBlock(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// The review's case: blocks written before a restart, and a database that
// stops answering after it. Every block in force is enforced, at once, and
// without a single lookup; what is not in force is not.
func TestABlockInForceIsEnforcedAfterARestartWithTheDatabaseHung(t *testing.T) {
	onEachPreloadEngine(t, func(t *testing.T, url string) {
		w := writeBlocksBeforeARestart(t)
		restartStore(t, url)
		h := hangLookups(t)
		for _, ip := range append(w.blockedIPs, "2001:db8:77:1:ffff::9") {
			if !decidedWithin(t, ip, func() bool { return IsIPMitigatedContext(t.Context(), ip) }) {
				t.Errorf("%s: blocked before the restart, served after it with the database hung", ip)
			}
		}
		for _, key := range w.blockedKeys {
			if !decidedWithin(t, key, func() bool { return IsUserMitigatedContext(t.Context(), key) }) {
				t.Errorf("fingerprint %s: blocked before the restart, served after it", key)
			}
		}
		if n := h.Queries(); n != 0 {
			t.Errorf("%d lookups to enforce blocks the list holds, want none", n)
		}
		// Not in force: decided as before, by a lookup that cannot finish.
		if decidedWithin(t, w.lapsedIP, func() bool { return IsIPMitigatedContext(t.Context(), w.lapsedIP) }) {
			t.Errorf("%s: a lapsed shun was enforced", w.lapsedIP)
		}
		if decidedWithin(t, w.releasedKey, func() bool { return IsUserMitigatedContext(t.Context(), w.releasedKey) }) {
			t.Errorf("a released fingerprint block was enforced")
		}
	})
}

// saturate holds every lookup slot with a lookup of a new address that the
// hung database never answers, and checks that the next new address finds the
// gate saturated.
func saturate(t *testing.T) {
	t.Helper()
	slots := getStore().lookups.slots.Cap()
	var wg sync.WaitGroup
	for i := range slots {
		wg.Go(func() { IsIPMitigatedContext(t.Context(), fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)) })
	}
	wg.Wait()
	before := lookupErrors(mitigationLookupIP, lookupReasonSaturated)
	IsIPMitigated("198.51.100.250")
	if lookupErrors(mitigationLookupIP, lookupReasonSaturated) == before {
		t.Fatalf("control: the gate is not saturated (%d slots held of %d)", getStore().lookups.slots.InFlight(), slots)
	}
}

// What an attacker with many addresses can force: every lookup slot held.
// A block in force is enforced anyway, and does not count as a saturated
// lookup -- it was never one.
func TestABlockInForceIsEnforcedWhileTheLookupsAreSaturated(t *testing.T) {
	onEachPreloadEngine(t, func(t *testing.T, url string) {
		w := writeBlocksBeforeARestart(t)
		restartStore(t, url)
		hangLookups(t)
		saturate(t)
		before := lookupErrors(mitigationLookupIP, lookupReasonSaturated)
		beforeUser := lookupErrors(mitigationLookupUser, lookupReasonSaturated)
		for _, ip := range w.blockedIPs {
			if !IsIPMitigated(ip) {
				t.Errorf("%s: served while the lookups were saturated", ip)
			}
		}
		for _, key := range w.blockedKeys {
			if !IsUserMitigated(key) {
				t.Errorf("fingerprint %s: served while the lookups were saturated", key)
			}
		}
		if got := lookupErrors(mitigationLookupIP, lookupReasonSaturated) - before +
			lookupErrors(mitigationLookupUser, lookupReasonSaturated) - beforeUser; got != 0 {
			t.Errorf("%v saturated lookups for blocks the list holds, want none", got)
		}
	})
}

// A block this node writes is enforced from the list once the cache has
// forgotten it -- the cache holds 1,000 answers by default, and a flood of new
// addresses evicts them -- with the database hung.
func TestThisNodesBlockIsEnforcedAfterTheCacheForgotIt(t *testing.T) {
	onEachPreloadEngine(t, func(t *testing.T, _ string) {
		const ip = "198.51.100.211"
		key := repid.For(scopeChrome, "198.18.4.1")
		mustBlock(t, MarkIPMitigated(ip, "operator"))
		MarkUserMitigated(key, "JA4+", "test", "waf")
		getStore().unmitigatedCache.Purge()
		getStore().userMitigationCache.Purge()
		h := hangLookups(t)
		if !decidedWithin(t, ip, func() bool { return IsIPMitigated(ip) }) {
			t.Error("a block this node wrote was served once the cache forgot it")
		}
		if !decidedWithin(t, key, func() bool { return IsUserMitigated(key) }) {
			t.Error("a fingerprint block this node wrote was served once the cache forgot it")
		}
		if n := h.Queries(); n != 0 {
			t.Errorf("%d lookups, want none", n)
		}
	})
}

// A release on this node takes effect at once, whatever the list read before
// it holds, and a read of the list afterwards does not bring the block back.
func TestAReleaseIsNotUndoneByTheBlockList(t *testing.T) {
	onEachPreloadEngine(t, func(t *testing.T, url string) {
		w := writeBlocksBeforeARestart(t)
		restartStore(t, url)
		ip, key := w.blockedIPs[0], w.blockedKeys[0]
		mustBlock(t, MarkIPUnmitigated(ip))
		ReleaseUserMitigationClass(key)
		for _, reread := range []bool{false, true} {
			if reread {
				getStore().readBlockList(true)
			}
			getStore().unmitigatedCache.Purge()
			getStore().userMitigationCache.Purge()
			if IsIPMitigated(ip) {
				t.Errorf("reread=%v: %s was released on this node and refused", reread, ip)
			}
			if IsUserMitigated(key) {
				t.Errorf("reread=%v: fingerprint %s was released on this node and refused", reread, key)
			}
		}
	})
}

// The list is read again on a schedule, so a block written on another node --
// straight to the database -- is enforced without a lookup from the next read,
// and a release there ends it.
func TestAnotherNodesBlockAndReleaseReachTheListOnTheNextRead(t *testing.T) {
	onEachPreloadEngine(t, func(t *testing.T, _ string) {
		const ip = "198.51.100.212"
		s := getStore()
		if _, err := s.db.Exec(s.dialect.Rebind(`INSERT INTO ip_mitigations (ip, status, reason, mitigated_at, updated_at)
			VALUES (?, 'mitigated', 'other node', ?, CURRENT_TIMESTAMP)`), ip, sqlUTC(time.Now())); err != nil {
			t.Fatal(err)
		}
		s.readBlockList(true)
		h := hangLookups(t)
		if !decidedWithin(t, ip, func() bool { return IsIPMitigated(ip) }) || h.Queries() != 0 {
			t.Fatalf("another node's block was not enforced from the list (%d lookups)", h.Queries())
		}
		if _, err := s.db.Exec(s.dialect.Rebind(QueryReleaseIPMitigation), sqlUTC(time.Now()), ip); err != nil {
			t.Fatal(err)
		}
		s.readBlockList(true)
		s.unmitigatedCache.Purge()
		if s.listedIPBlock(ip) {
			t.Fatal("another node's release did not reach the list")
		}
	})
}

// A list larger than the bound holds the newest blocks and says it is cut
// short; the older ones are enforced by a lookup, as every block was before
// the list existed.
func TestABlockListLargerThanItsBoundHoldsTheNewest(t *testing.T) {
	prev := blockListBounds
	blockListBounds.Entries = 3
	t.Cleanup(func() { blockListBounds = prev })
	onEachPreloadEngine(t, func(t *testing.T, url string) {
		ips := []string{"198.51.100.221", "198.51.100.222", "198.51.100.223", "198.51.100.224", "198.51.100.225"}
		for i, ip := range ips {
			mustBlock(t, MarkIPMitigated(ip, "operator"))
			ageIPShun(t, ip, time.Duration(len(ips)-i)*time.Minute) // the last is the newest
		}
		restartStore(t, url)
		if n, _, complete, _ := getStore().blocks.Size(); n != 3 || complete {
			t.Fatalf("the list holds %d address blocks, complete %v; want 3, cut short", n, complete)
		}
		if got := testGaugeValue(t, BlockListComplete.WithLabelValues(mitigationLookupIP)); got != 0 {
			t.Errorf("gateon_mitigation_block_list_complete{kind=ip} = %v, want 0", got)
		}
		for _, ip := range ips[:2] { // the oldest: left to the lookup, which finds them
			if !IsIPMitigated(ip) {
				t.Errorf("%s: an older block past the bound was not enforced by its lookup", ip)
			}
		}
		getStore().unmitigatedCache.Purge()
		h := hangLookups(t)
		for _, ip := range ips[2:] {
			if !decidedWithin(t, ip, func() bool { return IsIPMitigated(ip) }) {
				t.Errorf("%s: one of the newest blocks was served with the database hung", ip)
			}
		}
		if n := h.Queries(); n != 0 {
			t.Errorf("%d lookups for blocks the list holds, want none", n)
		}
	})
}

func testGaugeValue(t *testing.T, g interface{ Write(*dto.Metric) error }) float64 {
	t.Helper()
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetGauge().GetValue()
}
