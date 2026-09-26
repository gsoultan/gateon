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

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// quietStore builds a store as NewIPReputationStore does, minus the background
// refresh its constructor starts, so the test decides when every load happens.
func quietStore(urls ...string) *IPReputationStore {
	return &IPReputationStore{
		badIPs: make(map[string]float64),
		trie:   newIPTrie(),
		config: &gateonv1.IPReputationConfig{Enabled: true, FeedUrls: urls},
	}
}

// feedBlocks is the predicate the WAF's feed rule applies: listed, and at or
// above the block threshold.
func feedBlocks(s *IPReputationStore, ip string) bool {
	bad, score := s.IsBad(ip)
	return bad && score >= s.GetBlockThreshold()
}

// TestFailedRefreshKeepsTheBlocklist is the regression test for a refresh that
// emptied the blocklist whenever the feed could not be read.
//
// update built a fresh set from every configured feed and swapped it in
// unconditionally. A feed that could not be reached contributed nothing and
// only logged; a feed that answered with an error page contributed nothing and
// did not even log, because the status was never checked and an HTML body
// parses as zero addresses. Either way the swap replaced a full blocklist with
// an empty one, and it stayed empty until the next refresh -- 24 hours by
// default -- while nothing reported that the feed had been lost. A provider's
// rate limit or a moment's outage at refresh time was enough.
func TestFailedRefreshKeepsTheBlocklist(t *testing.T) {
	const listed = "203.0.113.60"

	var failure atomic.Int32 // 0: serve the feed, 1: error page, 2: new list
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch failure.Load() {
		case 1:
			http.Error(w, "<html>503 Service Unavailable</html>", http.StatusServiceUnavailable)
		case 2:
			fmt.Fprintln(w, "198.51.100.61")
		default:
			fmt.Fprintln(w, listed)
		}
	}))
	t.Cleanup(feed.Close)

	ctx := context.Background()
	store := quietStore(feed.URL)
	store.update(ctx)
	if !feedBlocks(store, listed) {
		t.Fatal("setup: the listed address is not blocked after the first load")
	}

	failure.Store(1)
	store.update(ctx)
	if !feedBlocks(store, listed) {
		t.Fatal("a refresh that got a 503 emptied the blocklist: the listed address is no longer blocked")
	}

	unreachable := quietStore(feed.URL)
	failure.Store(0)
	unreachable.update(ctx)
	feed.Close()
	unreachable.update(ctx)
	if !feedBlocks(unreachable, listed) {
		t.Fatal("a refresh that could not reach the feed emptied the blocklist")
	}

	// A refresh that succeeds still replaces the list, or keeping the last good
	// copy has simply frozen it.
	fresh := httptest.NewServer(feed.Config.Handler)
	t.Cleanup(fresh.Close)
	replaced := quietStore(fresh.URL)
	replaced.update(ctx)
	failure.Store(2)
	replaced.update(ctx)
	if feedBlocks(replaced, listed) || !feedBlocks(replaced, "198.51.100.61") {
		t.Fatal("a successful refresh did not replace the list with what the feed now says")
	}
}

// TestRemovingTheFeedsTakesTheirEntriesOutOfForce is the regression test for a
// blocklist that outlived the configuration that asked for it.
//
// Reconfigure only ever started a refresh, and a refresh with no feeds to read
// returned without touching the loaded set, while a disabled store was not
// refreshed at all. So an operator who removed a feed that was blocking a
// customer, or switched IP reputation off, saved successfully and the listed
// addresses stayed refused until the gateway restarted.
func TestRemovingTheFeedsTakesTheirEntriesOutOfForce(t *testing.T) {
	const listed = "203.0.113.70"
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, listed)
	}))
	t.Cleanup(feed.Close)

	for name, next := range map[string]*gateonv1.IPReputationConfig{
		"feeds removed":         {Enabled: true},
		"reputation turned off": {Enabled: false, FeedUrls: []string{feed.URL}},
	} {
		t.Run(name, func(t *testing.T) {
			store := quietStore(feed.URL)
			store.update(context.Background())
			if !feedBlocks(store, listed) {
				t.Fatal("setup: the listed address is not blocked after the first load")
			}

			store.Reconfigure(next)
			if feedBlocks(store, listed) {
				t.Fatal("the configuration no longer asks for this feed, and its entries are still refused")
			}

			// A scheduled refresh must not bring them back either.
			store.update(context.Background())
			if feedBlocks(store, listed) {
				t.Fatal("a refresh after the change put the removed entries back in force")
			}
		})
	}
}
