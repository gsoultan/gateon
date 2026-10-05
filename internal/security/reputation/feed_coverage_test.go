// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package reputation

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// slashEights lists n IPv4 /8s from first.0.0.0.
func slashEights(first, n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "%d.0.0.0/8\n", first+i)
	}
	return b.String()
}

// TestFeedsTogetherCannotListEveryone is review 3's F5. Each line was bounded
// to a /8, but nothing bounded them together: 256 lines "N.0.0.0/8" -- far
// inside every tier's entry bound -- refused every IPv4 client on every
// entrypoint, which ADR 0061's title says a feed cannot do. The address space
// every feed covers together is bounded per family, by default one /4's worth
// of IPv4 (sixteen /8s) and one /32's worth of IPv6; entries past it are
// refused and counted as coverage.
func TestFeedsTogetherCannotListEveryone(t *testing.T) {
	slash8s := int(currentFeedLimits().cover4 >> 24) // /8s the default admits
	if slash8s < 1 || slash8s >= 256 {
		t.Fatalf("setup: the default IPv4 coverage admits %d /8s; the test needs some admitted and some refused", slash8s)
	}
	before := refusedCount(t, refusedCoverage)
	var v6 strings.Builder
	for i := range 300 {
		fmt.Fprintf(&v6, "2%03x::/32\n", i)
	}
	s := loadedStore(t, serveFeed(t, slashEights(0, 256)+v6.String()))

	firstRefused := fmt.Sprintf("%d.1.2.3", slash8s)
	for _, ip := range []string{firstRefused, "200.1.2.3", "255.255.255.1", "2100::1", "2128::1"} {
		if bad, _ := s.IsBad(ip); bad {
			t.Errorf("%s is listed: the feed covers more than the IPv4 or IPv6 coverage bound", ip)
		}
	}
	lastAdmitted := fmt.Sprintf("%d.1.2.3", slash8s-1)
	for _, ip := range []string{"0.1.2.3", lastAdmitted, "2000::1"} {
		if bad, _ := s.IsBad(ip); !bad {
			t.Errorf("%s, inside the coverage bound, is not listed", ip)
		}
	}
	if got, want := refusedCount(t, refusedCoverage)-before, float64(256-slash8s+299); got != want {
		t.Errorf("coverage counter moved by %v, want %v", got, want)
	}
}

// TestTheDefaultCoverageAdmitsTheBogonsOfACommonFeed: FireHOL level 1, the
// feed most installs start with, lists bogon and private ranges worth four to
// five /8s. A one-/8 default took entries of it out of force on upgrade.
func TestTheDefaultCoverageAdmitsTheBogonsOfACommonFeed(t *testing.T) {
	const bogons = "0.0.0.0/8\n10.0.0.0/8\n100.64.0.0/10\n127.0.0.0/8\n169.254.0.0/16\n" +
		"172.16.0.0/12\n192.0.0.0/24\n192.0.2.0/24\n192.168.0.0/16\n198.18.0.0/15\n" +
		"198.51.100.0/24\n203.0.113.0/24\n"
	before := refusedCount(t, refusedCoverage)
	s := loadedStore(t, serveFeed(t, bogons))
	if got := refusedCount(t, refusedCoverage) - before; got != 0 {
		t.Errorf("the default coverage refused %v of a common feed's bogon entries", got)
	}
	for _, ip := range []string{"10.1.1.1", "127.0.0.2", "192.168.1.1", "100.64.0.1"} {
		if bad, _ := s.IsBad(ip); !bad {
			t.Errorf("%s, a bogon the feed lists, is not listed", ip)
		}
	}
}

// TestCoverageIsSharedAcrossFeedsAndTunable: the bound is across every feed,
// in configured order like the entry bound, and its environment variable
// widens or narrows it; a value out of range keeps the default.
func TestCoverageIsSharedAcrossFeedsAndTunable(t *testing.T) {
	t.Setenv(feedCoverageV4Env, "7") // two /8s' worth
	first := serveFeed(t, "10.0.0.0/8\n")
	second := serveFeed(t, "11.0.0.0/8\n12.0.0.0/8\n")
	s := loadedStore(t, first, second)
	for ip, want := range map[string]bool{"10.1.1.1": true, "11.1.1.1": true, "12.1.1.1": false} {
		if bad, _ := s.IsBad(ip); bad != want {
			t.Errorf("%s listed=%v, want %v under a coverage of one /7", ip, bad, want)
		}
	}

	for _, v := range []string{"0", "33", "x"} {
		t.Setenv(feedCoverageV4Env, v)
		if got := currentFeedLimits().cover4; got != 1<<28 {
			t.Errorf("%s=%q gives a coverage of %d addresses, want the default %d", feedCoverageV4Env, v, got, 1<<28)
		}
	}
	t.Setenv(feedCoverageV6Env, "16")
	if got := currentFeedLimits().cover6; got != 1<<48 {
		t.Errorf("%s=16 gives %d /64s, want %d", feedCoverageV6Env, got, uint64(1)<<48)
	}
}

// TestAFailedFeedKeepsItsCopyOnlyWithinTheCoverage: a last good copy draws on
// the coverage bound like a fresh read, so lowering the bound under it drops
// it rather than holding it over the bound.
func TestAFailedFeedKeepsItsCopyOnlyWithinTheCoverage(t *testing.T) {
	t.Setenv(feedCoverageV4Env, "7")
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "10.0.0.0/8\n11.0.0.0/8\n")
	}))
	defer srv.Close()
	s := loadedStore(t, srv.URL)
	if got := s.index.Load().entries; got != 2 {
		t.Fatalf("%d entries in force, want 2", got)
	}
	down.Store(true)
	t.Setenv(feedCoverageV4Env, "8")
	before := refusedCount(t, refusedCoverage)
	s.update(t.Context())
	if got := s.index.Load().entries; got != 0 {
		t.Errorf("a last good copy covering two /8s stayed in force under a coverage of one (%d entries)", got)
	}
	if got := refusedCount(t, refusedCoverage) - before; got != 2 {
		t.Errorf("coverage counter moved by %v, want 2", got)
	}
}
