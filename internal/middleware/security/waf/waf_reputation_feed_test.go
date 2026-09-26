// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/security/reputation"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// serveFrom sends one request through h from the given client address and
// returns the status.
func serveFrom(h http.Handler, ip string) int {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = ip + ":40200"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

// feedWAF builds the WAF over a reputation store loaded from a plain-text feed
// served by a loopback test server, the way an operator configures one.
func feedWAF(t *testing.T, cfg *gateonv1.IPReputationConfig) http.Handler {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	store := reputation.NewIPReputationStore(cfg)
	store.Start(ctx) // the first load is synchronous

	mw, err := WAF(WAFConfig{ParanoiaLevel: 1, EnableIPReputation: true, Reputation: store})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}
	return mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

// TestWAF_ReputationFeedBlocksWhatItLists is the regression test for a feed
// that loaded, logged its size, and blocked nothing.
//
// A plain-text feed says one thing about an address: refuse it. The loader
// stored every entry with a score of 1.0, and the WAF refuses a listed address
// only when that score reaches the block threshold -- 80 by default, and 80 is
// what the dashboard recommends. So at the default and at the recommended
// setting, rule 1910001 ("IP reputation block (external feed)") could never
// fire, while the store reported "IP reputation store updated" with every
// entry counted.
func TestWAF_ReputationFeedBlocksWhatItLists(t *testing.T) {
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "# test feed")
		fmt.Fprintln(w, "203.0.113.50")
		fmt.Fprintln(w, "198.51.100.0/24 # a listed network")
	}))
	t.Cleanup(feed.Close)

	for _, threshold := range []float64{0, 80} {
		t.Run(fmt.Sprintf("threshold %v", threshold), func(t *testing.T) {
			h := feedWAF(t, &gateonv1.IPReputationConfig{
				Enabled:        true,
				FeedUrls:       []string{feed.URL},
				BlockThreshold: threshold,
			})

			if got := serveFrom(h, "192.0.2.10"); got != http.StatusOK {
				t.Fatalf("setup: an address the feed does not list got %d, want 200", got)
			}
			for _, listed := range []string{"203.0.113.50", "198.51.100.77"} {
				if got := serveFrom(h, listed); got != http.StatusForbidden {
					t.Errorf("%s is listed by the feed and got %d, want 403", listed, got)
				}
			}
		})
	}
}
