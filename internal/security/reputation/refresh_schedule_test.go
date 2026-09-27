// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package reputation

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Addresses the switchingFeed serves before and after the test flips it.
const (
	listedFirst = "203.0.113.110"
	listedLater = "198.51.100.110"
)

// switchingFeed serves listedFirst until flipped, listedLater afterwards, and
// counts the requests it has answered.
type switchingFeed struct {
	*httptest.Server
	flipped atomic.Bool
	served  atomic.Int32
}

func newSwitchingFeed(t *testing.T) *switchingFeed {
	t.Helper()
	f := &switchingFeed{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if f.flipped.Load() {
			fmt.Fprintln(w, listedLater)
		} else {
			fmt.Fprintln(w, listedFirst)
		}
		f.served.Add(1)
	}))
	t.Cleanup(f.Close)
	return f
}

// shortRefreshUnit makes one update_interval_hours worth d for one test, so a
// schedule measured in hours runs in milliseconds.
func shortRefreshUnit(t *testing.T, d time.Duration) {
	t.Helper()
	prev := refreshUnit
	refreshUnit = d
	t.Cleanup(func() { refreshUnit = prev })
}

// startJoined starts store and, at cleanup, stops its refresh loop and waits
// for it to return. Registered after shortRefreshUnit or shortFeedTimeout, it
// runs before them, so no loop is still reading a package variable when they
// put it back.
func startJoined(t *testing.T, store *IPReputationStore) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	store.Start(ctx)
	joinOnCleanup(t, store, cancel)
}

// joinOnCleanup stops a started store's refresh loop at cleanup and waits for
// it to return.
func joinOnCleanup(t *testing.T, store *IPReputationStore, cancel context.CancelFunc) {
	t.Helper()
	t.Cleanup(func() {
		cancel()
		<-store.loopDone
	})
}

// eventually polls cond until it holds or d passes.
func eventually(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// servedAtLeast waits until the feed has answered n requests.
func (f *switchingFeed) servedAtLeast(t *testing.T, n int32) {
	t.Helper()
	if !eventually(5*time.Second, func() bool { return f.served.Load() >= n }) {
		t.Fatalf("setup: the feed answered %d requests, want at least %d", f.served.Load(), n)
	}
}

// TestFeedsEnabledAfterBootAreRefreshed is the regression test for feeds that
// were loaded once and never again.
//
// Start built the refresh ticker only when IP reputation was already enabled at
// boot, and returned without one otherwise. The stock configuration ships it
// switched off, so the ordinary path -- install, then switch it on in the
// dashboard -- loaded each feed once, from the save, and never refreshed it
// until the gateway restarted. The interval the dashboard asks for ("How often
// to sync feeds") was never consulted, and a feed that listed an address after
// that save was never enforced.
func TestFeedsEnabledAfterBootAreRefreshed(t *testing.T) {
	shortRefreshUnit(t, 20*time.Millisecond)
	feed := newSwitchingFeed(t)

	store := NewIPReputationStore(&gateonv1.IPReputationConfig{})
	startJoined(t, store)

	store.Reconfigure(&gateonv1.IPReputationConfig{
		Enabled: true, FeedUrls: []string{feed.URL}, UpdateIntervalHours: 1,
	})
	if !eventually(5*time.Second, func() bool { return feedBlocks(store, listedFirst) }) {
		t.Fatal("setup: switching IP reputation on did not load the feed")
	}

	feed.flipped.Store(true)
	if !eventually(5*time.Second, func() bool { return feedBlocks(store, listedLater) }) {
		t.Fatalf("the feed now lists %s and it is still not refused after %d scheduled "+
			"intervals: feeds switched on after boot are never refreshed",
			listedLater, int((5*time.Second)/refreshUnit))
	}
}

// TestAChangedIntervalIsTheOneThatRuns is the regression test for an update
// interval that could only be set at boot.
//
// The ticker was built once, from the interval in force at startup. A save that
// changed it -- to refresh a fast-moving feed hourly instead of daily -- stored
// the new value, showed it in the dashboard, and kept refreshing on the old
// schedule until a restart.
func TestAChangedIntervalIsTheOneThatRuns(t *testing.T) {
	shortRefreshUnit(t, 20*time.Millisecond)
	feed := newSwitchingFeed(t)

	cfg := func(hours int32) *gateonv1.IPReputationConfig {
		return &gateonv1.IPReputationConfig{
			Enabled: true, FeedUrls: []string{feed.URL}, UpdateIntervalHours: hours,
		}
	}
	// A year between refreshes: nothing scheduled happens during this test
	// unless the new interval takes over.
	store := NewIPReputationStore(cfg(maxUpdateIntervalHours))
	startJoined(t, store)
	if !feedBlocks(store, listedFirst) {
		t.Fatal("setup: Start did not load the feed")
	}

	store.Reconfigure(cfg(1))
	// The save refreshes once on its own; only a refresh after it is scheduled.
	feed.servedAtLeast(t, 2)
	feed.flipped.Store(true)

	if !eventually(5*time.Second, func() bool { return feedBlocks(store, listedLater) }) {
		t.Fatal("the interval was changed to one hour and no refresh ran on it; " +
			"the schedule set at boot is still the one in force")
	}
}
