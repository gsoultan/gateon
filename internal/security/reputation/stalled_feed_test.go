// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package reputation

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// stalledFeed is a feed server that accepts every request and answers none of
// them until the test ends: a provider that is up at the TCP level and stuck
// behind it, or a slow-drip body. It is the failure a timeout exists for, and
// the one an unreachable address -- refused at once -- never exercises.
//
// The handler returns when the test is over, so Close does not wait forever.
// Each request that arrives is announced on the returned channel, so a test can
// wait until a fetch is really in flight instead of sleeping and hoping.
func stalledFeed(t *testing.T) (*httptest.Server, <-chan struct{}) {
	t.Helper()
	release := make(chan struct{})
	arrived := make(chan struct{}, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case arrived <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})
	return srv, arrived
}

// shortFeedTimeout bounds a feed fetch for the length of one test.
func shortFeedTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	prev := feedFetchTimeout
	feedFetchTimeout = d
	t.Cleanup(func() { feedFetchTimeout = prev })
}

// returnsWithin runs fn and reports whether it finished inside d.
func returnsWithin(d time.Duration, fn func()) bool {
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// TestStartIsNotHeldByAFeedThatNeverAnswers is the regression test for a boot
// that never finished.
//
// main calls Start synchronously before any listener opens, and every feed was
// fetched with http.DefaultClient, which has no timeout. A feed that accepted
// the connection and then sent nothing held the fetch -- and so Start, and so
// the whole gateway -- for as long as the provider kept the socket open. A
// provider's bad afternoon was a gateway that would not start, and under an
// orchestrator's startup probe, one that restarted in a loop.
func TestStartIsNotHeldByAFeedThatNeverAnswers(t *testing.T) {
	shortFeedTimeout(t, 200*time.Millisecond)
	feed, _ := stalledFeed(t)

	store := NewIPReputationStore(&gateonv1.IPReputationConfig{
		Enabled:  true,
		FeedUrls: []string{feed.URL},
	})
	if !returnsWithin(5*time.Second, func() { store.Start(t.Context()) }) {
		t.Fatal("Start is still waiting on a feed that accepted the connection and " +
			"never answered; the gateway never finishes booting")
	}
}

// TestSwitchingFeedsOffIsNotHeldByAStalledFetch is the regression test for a
// settings save that did not return.
//
// Switching IP reputation off takes the loaded entries out of force
// synchronously, and to do that safely it waits for the refresh in flight. With
// no timeout on the fetch that refresh could be waiting on a stalled provider
// indefinitely, so the save -- the operator's way out of a feed that is
// misbehaving -- hung behind exactly the feed it was meant to get rid of. The
// feed's timeout here is far longer than the test is prepared to wait: the
// save must not depend on it.
func TestSwitchingFeedsOffIsNotHeldByAStalledFetch(t *testing.T) {
	shortFeedTimeout(t, time.Hour)
	feed, arrived := stalledFeed(t)
	const listed = "203.0.113.90"
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, listed)
	}))
	t.Cleanup(good.Close)

	store := quietStore(good.URL)
	store.update(context.Background())
	if !feedBlocks(store, listed) {
		t.Fatal("setup: the listed address is not blocked after the first load")
	}

	// A refresh against the stalled provider, as the ticker or a previous save
	// would have started it, is in flight when the operator switches feeds off.
	store.Reconfigure(&gateonv1.IPReputationConfig{Enabled: true, FeedUrls: []string{feed.URL}})
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("setup: the refresh never reached the stalled feed")
	}

	off := &gateonv1.IPReputationConfig{Enabled: false}
	if !returnsWithin(3*time.Second, func() { store.Reconfigure(off) }) {
		t.Fatal("switching IP reputation off is still waiting on a feed fetch that " +
			"never finishes; the settings save does not return")
	}
	if feedBlocks(store, listed) {
		t.Fatal("IP reputation was switched off and the loaded entries are still refused")
	}
}
