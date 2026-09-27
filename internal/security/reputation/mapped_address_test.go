// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package reputation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// feedStore loads a store from a feed serving body.
func feedStore(t *testing.T, body string) *IPReputationStore {
	t.Helper()
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(feed.Close)
	store := quietStore(feed.URL)
	store.update(context.Background())
	return store
}

// TestAListedAddressIsRefusedInEitherSpelling is the regression test for a feed
// that a v4-mapped address walked straight past.
//
// "::ffff:203.0.113.130" is 203.0.113.130: the spelling a proxy on a dual-stack
// socket writes for an IPv4 client -- Node's remoteAddress, HAProxy on a v4v6
// bind -- and the one the client resolver passes on as the proxy wrote it.
// The mitigation allowlist unmaps it for exactly that reason, and so does the
// reputation identity. The feed store did not: it looked the mapped form up in
// its IPv6 trie, where no IPv4 entry lives, so behind such a proxy every IPv4
// entry of every feed -- in practice all of them -- refused nobody. The
// reverse held too: a feed that wrote an entry in the mapped form listed an
// address no IPv4 client ever matched.
func TestAListedAddressIsRefusedInEitherSpelling(t *testing.T) {
	t.Run("IPv4 entries, mapped clients", func(t *testing.T) {
		store := feedStore(t, "203.0.113.130\n198.51.100.0/24\n")
		for _, client := range []string{"::ffff:203.0.113.130", "::ffff:198.51.100.7"} {
			if !feedBlocks(store, client) {
				t.Errorf("%s is a listed IPv4 address in its v4-mapped spelling and was not refused", client)
			}
		}
		for _, client := range []string{"203.0.113.131", "::ffff:203.0.113.131"} {
			if feedBlocks(store, client) {
				t.Errorf("%s is not listed in either spelling and was refused", client)
			}
		}
	})

	t.Run("mapped entries, IPv4 clients", func(t *testing.T) {
		store := feedStore(t, "::ffff:192.0.2.10\n::ffff:192.0.2.128/121\n")
		for _, client := range []string{"192.0.2.10", "192.0.2.200", "::ffff:192.0.2.200"} {
			if !feedBlocks(store, client) {
				t.Errorf("%s is listed by the feed in v4-mapped form and was not refused", client)
			}
		}
		if feedBlocks(store, "192.0.2.11") {
			t.Error("192.0.2.11 is not listed and was refused")
		}
	})
}
