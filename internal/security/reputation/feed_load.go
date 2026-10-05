// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package reputation

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/gsoultan/gateon/internal/config"
)

// What a feed may put in force (ADR 0061).

// Environment overrides of the tier's feed bounds (config.TierDefaults).
const (
	feedMaxEntriesEnv = "GATEON_IP_FEED_MAX_ENTRIES"
	feedMaxMBEnv      = "GATEON_IP_FEED_MAX_MB"
)

// feedLimits bound the entries in force across every feed.
type feedLimits struct {
	entries int
	bytes   int64
}

// currentFeedLimits is the tier's bounds, each overridden by its environment
// variable when that is a positive integer.
func currentFeedLimits() feedLimits {
	d := config.CurrentTierDefaults()
	l := feedLimits{entries: d.IPFeedMaxEntries, bytes: d.IPFeedMaxBytes}
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(feedMaxEntriesEnv))); err == nil && n > 0 {
		l.entries = n
	}
	if n, err := strconv.ParseInt(strings.TrimSpace(os.Getenv(feedMaxMBEnv)), 10, 64); err == nil && n > 0 {
		l.bytes = n << 20
	}
	return l
}

// The widest prefix a feed entry may be: an IPv4 /8 (16.7 million
// addresses, a whole legacy class A) and an IPv6 /32 (a regional registry's
// usual allocation to one network). A feed line "0.0.0.0/0" or "::/0" -- a
// typo, a feed that lists bogons, a compromised feed -- refused every client
// of that family on every entrypoint; anything wider than these bounds is
// not a reputation, it is an outage.
const (
	minFeedBitsV4 = 8
	minFeedBitsV6 = 32
)

// Reasons a feed entry is not put in force, as the counter's label.
const (
	refusedTooWide   = "too_wide"
	refusedOverLimit = "over_limit"
)

// Feed metrics. The refusal reasons are the two constants above; the gauges
// have no labels.
var (
	feedEntriesRefused = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gateon_ip_feed_entries_refused_total",
		Help: "IP reputation feed entries not put in force, by reason (too_wide, over_limit).",
	}, []string{"reason"})
	feedEntriesInForce = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gateon_ip_feed_entries",
		Help: "IP reputation feed entries in force, across every feed.",
	})
	feedIndexBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gateon_ip_feed_bytes",
		Help: "Bytes the IP reputation feeds hold in memory: the index and, with more than one feed, each feed's last good copy.",
	})
)

// feedBudget is what is left of the limits during one refresh; every feed
// draws on it in the order the feeds are configured.
type feedBudget struct {
	entries int
	bytes   int64
}

// take reserves room for one entry costing size bytes, if there is room.
func (b *feedBudget) take(size int64) bool {
	if b.entries < 1 || b.bytes < size {
		return false
	}
	b.entries--
	b.bytes -= size
	return true
}

// feedLoad is one feed as read: its ranges, what they cost, and what was
// refused and why.
type feedLoad struct {
	// build collects the entries as they are read; ranges is what they
	// became once the feed was read in full.
	build     rangeBuilder
	ranges    feedRanges
	entries   int
	bytes     int64
	tooWide   int
	overLimit int
	// widest is the first too-wide entry, for the log.
	widest string
}

// accept counts p against budget and adds it, or records why not.
func (l *feedLoad) accept(p netip.Prefix, budget *feedBudget) {
	if tooWide(p) {
		l.tooWide++
		if l.widest == "" {
			l.widest = p.String()
		}
		return
	}
	size := entryBytes(p)
	if !budget.take(size) {
		l.overLimit++
		return
	}
	l.build.add(p)
	l.entries++
	l.bytes += size
}

// tooWide reports whether p covers more than a feed entry may.
func tooWide(p netip.Prefix) bool {
	if p.Addr().Is4() {
		return p.Bits() < minFeedBitsV4
	}
	return p.Bits() < minFeedBitsV6
}

// errFeedScheme refuses a feed that is not fetched over HTTPS.
var errFeedScheme = errors.New("an IP reputation feed must be an https:// URL (http:// is accepted only for a " +
	"feed on this host's loopback address)")

// checkFeedURL refuses a feed URL the gateway will not fetch.
//
// A feed decides whom every entrypoint refuses, so whoever can rewrite it in
// transit decides that too: over plain http:// anyone on the path could list
// the gateway's own customers, or one line of "0.0.0.0/0". It must be
// https://. Plain http:// is accepted only to a loopback address -- a mirror
// on the gateway's own host, where there is no network path to tamper on. A
// private network is a network; a mirror there needs TLS like any other.
func checkFeedURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return fmt.Errorf("IP reputation feed %q is not an absolute URL", raw)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if loopbackHost(u.Hostname()) {
			return nil
		}
	}
	return fmt.Errorf("%w: %q", errFeedScheme, raw)
}

// loopbackHost reports whether host names this machine's loopback.
func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Unmap().IsLoopback()
}

// ValidateFeedURLs refuses, at save, a feed URL that proposed adds and the
// gateway would not fetch (checkFeedURL). A URL already stored is not judged
// again, so a feed stored before the rule does not hold every unrelated
// settings save hostage; it is refused, and logged, at every refresh instead.
func ValidateFeedURLs(stored, proposed []string) error {
	known := make(map[string]bool, len(stored))
	for _, u := range stored {
		known[u] = true
	}
	for _, u := range proposed {
		if known[u] {
			continue
		}
		if err := checkFeedURL(u); err != nil {
			return err
		}
	}
	return nil
}

// feedClient fetches feeds. It follows a redirect only to a URL checkFeedURL
// accepts: an https:// feed that redirected to http:// would otherwise be
// read in the clear.
var feedClient = newFeedClient(http.DefaultTransport)

func newFeedClient(rt http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: rt,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return checkFeedURL(req.URL.String())
		},
	}
}

// fetchFeed reads one plain-text feed: an address or CIDR per line, with "#"
// comments, drawing each entry it keeps from budget.
//
// Anything but a 2xx answer is an error. An error page is not an empty feed:
// its body parses as zero addresses, and taking that as the feed's answer would
// take every entry out of force. Entries past the budget are counted, not
// kept, so a feed of any size costs at most the budget.
func fetchFeed(ctx context.Context, rawURL string, budget *feedBudget) (*feedLoad, error) {
	if err := checkFeedURL(rawURL); err != nil {
		return nil, err
	}
	// The deadline covers the body as well as the headers: the scan below
	// reads through the same request context.
	ctx, cancel := context.WithTimeout(ctx, feedFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := feedClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("feed answered with status %d", resp.StatusCode)
	}

	// The budget is drawn on as lines are read; a feed that then fails gives
	// it back by not being installed, so draw on a copy.
	local := *budget
	load := &feedLoad{}
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		if p, ok := parseFeedLine(scanner.Text()); ok {
			load.accept(p, &local)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	*budget = local
	load.ranges = load.build.ranges()
	load.build = rangeBuilder{}
	return load, nil
}

// parseFeedLine turns one feed line into a prefix; a bare address becomes a
// host prefix. Blank lines, comments and anything unparseable are skipped.
func parseFeedLine(line string) (netip.Prefix, bool) {
	if idx := strings.Index(line, "#"); idx >= 0 {
		line = line[:idx]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return netip.Prefix{}, false
	}
	if strings.Contains(line, "/") {
		prefix, err := netip.ParsePrefix(line)
		return unmapPrefix(prefix), err == nil
	}
	addr, err := netip.ParseAddr(line)
	if err != nil {
		return netip.Prefix{}, false
	}
	return unmapPrefix(netip.PrefixFrom(addr, addr.BitLen())), true
}

// unmapPrefix files a v4-mapped entry under the IPv4 network it maps, where an
// IPv4 client's lookup goes. A prefix shorter than the mapped space (/96)
// covers more than IPv4 and is kept as written.
func unmapPrefix(p netip.Prefix) netip.Prefix {
	const mappedBits = 96
	if !p.IsValid() || !p.Addr().Is4In6() || p.Bits() < mappedBits {
		return p
	}
	return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-mappedBits)
}
