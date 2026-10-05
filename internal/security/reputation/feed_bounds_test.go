// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package reputation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// serveFeed serves body as a plain-text feed on loopback.
func serveFeed(t testing.TB, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// loadedStore is a store that has loaded the feeds at urls once.
func loadedStore(t *testing.T, urls ...string) *IPReputationStore {
	t.Helper()
	s := quietStore(urls...)
	s.update(context.Background())
	return s
}

// refusedCount reads gateon_ip_feed_entries_refused_total for reason.
func refusedCount(t *testing.T, reason string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != "gateon_ip_feed_entries_refused_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			if m.GetLabel()[0].GetValue() == reason {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// hostsFeed lists n consecutive addresses from 10.0.0.1.
func hostsFeed(n int) string {
	var b strings.Builder
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "10.%d.%d.%d\n", i>>16&0xff, i>>8&0xff, i&0xff)
	}
	return b.String()
}

// TestTheFeedIndexHoldsNoMoreThanItsEntryLimit is DP-N2: nothing bounded
// the feed index, so a feed of a million addresses held ~500 MiB and a
// million IPv6 ones ran the 2 GB host out of memory. Under a limit of 100
// entries, a feed of 150 puts its first 100 in force, and the other 50 are
// counted and not listed.
func TestTheFeedIndexHoldsNoMoreThanItsEntryLimit(t *testing.T) {
	t.Setenv(feedMaxEntriesEnv, "100")
	before := refusedCount(t, refusedOverLimit)
	s := loadedStore(t, serveFeed(t, hostsFeed(150)))
	if bad, _ := s.IsBad("10.0.0.100"); !bad {
		t.Fatal("the 100th entry, inside the limit, is not listed")
	}
	if bad, _ := s.IsBad("10.0.0.101"); bad {
		t.Fatal("the 101st entry is listed under a limit of 100 entries")
	}
	if got := s.index.Load().entries; got != 100 {
		t.Errorf("index holds %d entries, want 100", got)
	}
	if got := refusedCount(t, refusedOverLimit) - before; got != 50 {
		t.Errorf("over_limit counter moved by %v, want 50", got)
	}
}

// TestTheFeedIndexHoldsNoMoreThanItsByteLimit: the byte bound is what decides
// for IPv6, whose entries cost 32 bytes each. One MiB, less the 512 KiB the
// top lookup tables may take, holds 16383 of them.
func TestTheFeedIndexHoldsNoMoreThanItsByteLimit(t *testing.T) {
	t.Setenv(feedMaxMBEnv, "1")
	var b strings.Builder
	for i := range 40000 {
		fmt.Fprintf(&b, "2001:db8:%x::1\n", i)
	}
	s := loadedStore(t, serveFeed(t, b.String()))
	idx := s.index.Load()
	if idx.entries != 16383 {
		t.Errorf("index holds %d IPv6 entries under 1 MiB, want 16383", idx.entries)
	}
	if got := idx.ranges.bytes(); got > 1<<20 {
		t.Errorf("index holds %d bytes under a limit of 1 MiB", got)
	}
}

// TestTheLimitIsSharedAcrossFeeds: two feeds draw on one limit in the order
// they are configured.
func TestTheLimitIsSharedAcrossFeeds(t *testing.T) {
	t.Setenv(feedMaxEntriesEnv, "100")
	first := serveFeed(t, hostsFeed(60))
	second := serveFeed(t, "192.0.2.0/24\n198.51.100.1\n"+hostsFeed(60))
	s := loadedStore(t, first, second)
	if got := s.index.Load().entries; got != 100 {
		t.Errorf("two feeds put %d entries in force under a shared limit of 100", got)
	}
	if bad, _ := s.IsBad("192.0.2.9"); !bad {
		t.Error("the second feed's first entry is not listed")
	}
}

// TestAFeedCannotListEveryone is TRUTH-NEW-4: one feed line "0.0.0.0/0" or
// "::/0" refused every client of that family on every entrypoint. A prefix
// wider than an IPv4 /8 or an IPv6 /32 is refused and counted; the rest of
// the feed is in force.
func TestAFeedCannotListEveryone(t *testing.T) {
	// The bound on what all entries cover together (feed_coverage_test.go) is
	// widened, so this one sees only the bound on each entry.
	t.Setenv(feedCoverageV4Env, "6")
	before := refusedCount(t, refusedTooWide)
	s := loadedStore(t, serveFeed(t, "0.0.0.0/0\n::/0\n2.0.0.0/7\n2001::/31\n::ffff:0:0/96\n"+
		"198.51.100.0/24\n11.0.0.0/8\n2001:db8::/32\n"))
	for _, ip := range []string{"8.8.8.8", "3.1.2.3", "2606:4700::1", "2001:1::1"} {
		if bad, _ := s.IsBad(ip); bad {
			t.Errorf("%s is listed by a prefix wider than a feed entry may be", ip)
		}
	}
	for _, ip := range []string{"198.51.100.7", "11.200.0.1", "2001:db8::5"} {
		if bad, _ := s.IsBad(ip); !bad {
			t.Errorf("%s, inside a /8 or /32 entry, is not listed", ip)
		}
	}
	if got := refusedCount(t, refusedTooWide) - before; got != 5 {
		t.Errorf("too_wide counter moved by %v, want 5", got)
	}
}

// TestFeedURLsMustBeHTTPS is the other half of TRUTH-NEW-4: a feed decides
// whom every entrypoint refuses, and over plain http:// anyone on the path
// could rewrite it. Plain http:// is accepted only to loopback.
func TestFeedURLsMustBeHTTPS(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://feeds.example.com/drop.txt":  true,
		"HTTPS://feeds.example.com/drop.txt":  true,
		"http://127.0.0.1:8082/feed.txt":      true,
		"http://[::1]:8082/feed.txt":          true,
		"http://localhost/feed.txt":           true,
		"http://feeds.example.com/drop.txt":   false,
		"http://10.0.0.5/feed.txt":            false,
		"http://192.168.1.10/feed.txt":        false,
		"ftp://feeds.example.com/drop.txt":    false,
		"feeds.example.com/drop.txt":          false,
		"http://127.0.0.1.example.com/x.txt":  false,
		"http://[::ffff:127.0.0.1]:80/feed":   true,
		"https://[2001:db8::1]/feed.txt":      true,
		"http://[2001:db8::1]/feed.txt":       false,
		"https:///no-host":                    false,
		"http://localhost.example.net/a.txt":  false,
		"http://0.0.0.0/feed.txt":             false,
		"http://169.254.169.254/latest/feeds": false,
	} {
		if err := checkFeedURL(raw); (err == nil) != ok {
			t.Errorf("checkFeedURL(%q) = %v, want accepted=%v", raw, err, ok)
		}
	}
	if err := ValidateFeedURLs([]string{"http://old.example.com/x"}, []string{"http://old.example.com/x"}); err != nil {
		t.Errorf("a feed already stored was judged again at save: %v", err)
	}
	if err := ValidateFeedURLs(nil, []string{"http://new.example.com/x"}); err == nil {
		t.Error("a new http:// feed was accepted at save")
	}
}

// TestAStoredHTTPFeedIsNotFetched: a feed stored before the rule is refused
// at every refresh, so nothing read over the wire in the clear is in force.
func TestAStoredHTTPFeedIsNotFetched(t *testing.T) {
	_, err := fetchFeed(context.Background(), "http://192.0.2.1/feed.txt", &feedBudget{entries: 10, bytes: 1 << 10})
	if !errors.Is(err, errFeedScheme) {
		t.Fatalf("an http:// feed off loopback was not refused for its scheme: %v", err)
	}
}

// TestOneFeedIsHeldOnce: with a single feed the index is that feed's ranges,
// not a copy of them, and a feed configured twice is counted once.
func TestOneFeedIsHeldOnce(t *testing.T) {
	url := serveFeed(t, hostsFeed(30))
	s := loadedStore(t, url, url)
	idx := s.index.Load()
	if idx.entries != 30 {
		t.Errorf("a feed configured twice put %d entries in force, want 30", idx.entries)
	}
	if &idx.ranges.v4[0] != &s.lastGood[url].ranges.v4[0] {
		t.Error("the index holds a copy of the only feed's ranges rather than sharing them")
	}
}

// TestAnHTTPSFeedThatRedirectsToHTTPIsRefused: following a redirect from an
// https:// feed to an http:// one would read the feed in the clear after all.
func TestAnHTTPSFeedThatRedirectsToHTTPIsRefused(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://192.0.2.1/feed.txt", http.StatusFound)
	}))
	defer srv.Close()
	prev := feedClient
	feedClient = newFeedClient(srv.Client().Transport)
	t.Cleanup(func() { feedClient = prev })
	_, err := fetchFeed(context.Background(), srv.URL, &feedBudget{entries: 10, bytes: 1 << 10})
	if err == nil || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("a redirect to http:// was followed: %v", err)
	}
}

// TestAFailedFeedKeepsItsCopyOnlyWithinTheLimits: a feed that cannot be read
// keeps its last good copy in force, and that copy draws on the limits; if
// they were lowered under it, it is dropped rather than held over them.
func TestAFailedFeedKeepsItsCopyOnlyWithinTheLimits(t *testing.T) {
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, hostsFeed(50))
	}))
	defer srv.Close()
	s := loadedStore(t, srv.URL)
	down.Store(true)
	s.update(context.Background())
	if got := s.index.Load().entries; got != 50 {
		t.Fatalf("a failed refresh left %d entries, want the last good 50", got)
	}
	t.Setenv(feedMaxEntriesEnv, "10")
	s.update(context.Background())
	if got := s.index.Load().entries; got != 0 {
		t.Fatalf("a last good copy of 50 entries stayed in force under a limit of 10 (%d)", got)
	}
}

// randomPrefix is a prefix in a small corner of one family's space, mostly
// long and sometimes wide, so ranges nest, overlap and touch.
func randomPrefix(rng *rand.Rand) netip.Prefix {
	bits := 20 + rng.IntN(13)
	if rng.IntN(10) == 0 {
		bits = 10 + rng.IntN(10)
	}
	if rng.IntN(2) == 0 {
		a := netip.AddrFrom4([4]byte{byte(rng.IntN(64)), byte(rng.IntN(256)), byte(rng.IntN(256)), byte(rng.IntN(256))})
		return netip.PrefixFrom(a, bits).Masked()
	}
	var b [16]byte
	b[0], b[1] = 0x20, byte(rng.IntN(64))
	for i := 2; i < 16; i++ {
		b[i] = byte(rng.IntN(256))
	}
	return netip.PrefixFrom(netip.AddrFrom16(b), 4*bits).Masked()
}

// TestTheIndexAgreesWithPrefixContains checks the ranges, with and without
// their top lookup tables, against netip's own containment for random
// prefixes and addresses, boundaries included.
func TestTheIndexAgreesWithPrefixContains(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	var prefixes []netip.Prefix
	var rb rangeBuilder
	for range 2600 {
		p := randomPrefix(rng)
		prefixes = append(prefixes, p)
		rb.add(p)
	}
	plain := rb.ranges()
	indexed := unionRanges([]feedRanges{plain})
	if indexed.v4Top == nil || indexed.v6Top == nil {
		t.Fatalf("no top index was built for %d IPv4 and %d IPv6 ranges", len(plain.v4), len(plain.v6))
	}
	probe := func(a netip.Addr) {
		want := false
		for _, p := range prefixes {
			if p.Contains(a) {
				want = true
				break
			}
		}
		if got := plain.contains(a); got != want {
			t.Fatalf("contains(%s) = %v, want %v", a, got, want)
		}
		if got := indexed.contains(a); got != want {
			t.Fatalf("contains(%s) with the top index = %v, want %v", a, got, want)
		}
	}
	for _, p := range prefixes {
		probe(p.Addr())
		probe(p.Addr().Prev())
		last := lastAddr(p)
		probe(last)
		probe(last.Next())
	}
	for range 1000 {
		probe(randomPrefix(rng).Addr())
	}
}

// lastAddr is the last address in p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// TestFeedRangesAtTheEdgesOfTheAddressSpace: ranges that end on the last
// address of a family merge without wrapping.
func TestFeedRangesAtTheEdgesOfTheAddressSpace(t *testing.T) {
	var rb rangeBuilder
	for _, s := range []string{"255.255.255.0/24", "255.0.0.0/8", "ffff::/16", "ffff:ffff::/32",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "255.255.255.255/32"} {
		rb.add(netip.MustParsePrefix(s))
	}
	r := rb.ranges()
	if len(r.v4) != 1 || len(r.v6) != 1 {
		t.Fatalf("nested edge ranges did not merge: %v %v", r.v4, r.v6)
	}
	for _, a := range []string{"255.255.255.255", "255.0.0.0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"} {
		if !r.contains(netip.MustParseAddr(a)) {
			t.Errorf("%s is not contained", a)
		}
	}
	if r.contains(netip.MustParseAddr("254.255.255.255")) || r.contains(netip.MustParseAddr("fffe::1")) {
		t.Error("an address just below the edge ranges is contained")
	}
}

// TestAdjacentPrefixesBecomeOneRange: two halves of a network are one range,
// so a feed that splits its networks costs no more than one that does not.
func TestAdjacentPrefixesBecomeOneRange(t *testing.T) {
	var rb rangeBuilder
	for _, s := range []string{"10.0.0.0/25", "10.0.0.128/25", "2001:db8::/33", "2001:db8:8000::/33"} {
		rb.add(netip.MustParsePrefix(s))
	}
	if r := rb.ranges(); len(r.v4) != 1 || len(r.v6) != 1 {
		t.Errorf("adjacent halves stayed apart: %v %v", r.v4, r.v6)
	}
}
