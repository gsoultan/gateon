// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package reputation

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type IPReputationStore struct {
	mu           sync.RWMutex
	config       *gateonv1.IPReputationConfig
	integrations []reputationProvider

	// index is what the feeds list, replaced whole and never modified once
	// stored, so a lookup reads it with one atomic load and no lock: every
	// request on every entrypoint asks it (ADR 0044).
	index atomic.Pointer[feedIndex]
	// threshold is GetBlockThreshold as float64 bits, kept beside the index
	// for the same reason.
	threshold atomic.Uint64

	// feedMu serialises refreshes and guards lastGood.
	feedMu sync.Mutex
	// lastGood is what each configured feed said the last time it could be
	// read, keyed by URL, so a feed that fails at refresh time keeps its
	// entries in force. Only configured feeds are kept, and their ranges are
	// shared with the index, never copied.
	lastGood map[string]*feedLoad

	// cancelMu guards refreshCancel, which stops the refresh in flight.
	// Reconfigure calls it: that refresh is fetching for a configuration that
	// has just been replaced, and switching feeds off has to wait for it.
	cancelMu      sync.Mutex
	refreshCancel context.CancelFunc

	// loopOnce starts the refresh loop once, from Start. rescheduled carries a
	// configuration change to it, so a new interval takes effect at once, and
	// loopDone is closed when the loop has returned.
	loopOnce    sync.Once
	rescheduled chan struct{}
	loopDone    chan struct{}
}

// ReputationClient is the interface for external IP reputation providers.
type ReputationClient interface {
	CheckIP(ctx context.Context, ip string) (int, error)
}

type reputationProvider struct {
	config *gateonv1.IPReputationIntegration
	client ReputationClient
}

// feedIndex is one immutable generation of the entries in force: every feed's
// as merged ranges, and the scores SetIPScore set by address text.
type feedIndex struct {
	ips     map[string]float64
	ranges  feedRanges
	entries int
}

func newFeedIndex() *feedIndex {
	return &feedIndex{ips: map[string]float64{}}
}

// NewIPReputationStore builds a store for cfg. It loads nothing: Start does the
// first load.
//
// It used to go through Reconfigure, which starts a background refresh, and
// both callers then call Start, which refreshes again and waits for the first
// to finish -- so every boot fetched every feed twice, one after the other,
// before a listener opened.
func NewIPReputationStore(cfg *gateonv1.IPReputationConfig) *IPReputationStore {
	store := &IPReputationStore{rescheduled: make(chan struct{}, 1)}
	store.index.Store(newFeedIndex())
	store.configure(cfg)
	return store
}

// Reconfigure updates the store configuration and re-initializes integrations.
func (s *IPReputationStore) Reconfigure(cfg *gateonv1.IPReputationConfig) {
	s.configure(cfg)
	// Whatever is being fetched now is for the configuration just replaced.
	s.cancelRefresh()
	s.reschedule()

	// Nothing left to load means nothing left in force. This used to start a
	// refresh only when enabled, and a refresh with no feeds returned without
	// touching the loaded set, so removing the feed that was refusing a
	// customer -- or switching IP reputation off -- saved successfully and left
	// every listed address refused until the gateway restarted. Done here and
	// synchronously, so the change has taken effect when the save returns.
	if !feedsWanted(cfg) {
		s.clearFeeds()
		return
	}
	// Trigger an update in background to pick up new feed URLs immediately
	go s.update(context.Background())
}

// configure installs cfg and builds a client for each enabled integration.
func (s *IPReputationStore) configure(cfg *gateonv1.IPReputationConfig) {
	var integrations []reputationProvider
	for _, integration := range cfg.GetIntegrations() {
		if !integration.GetEnabled() {
			continue
		}
		if client := newReputationClient(integration); client != nil {
			integrations = append(integrations, reputationProvider{config: integration, client: client})
		}
	}
	s.mu.Lock()
	s.config = cfg
	s.integrations = integrations
	s.mu.Unlock()
	s.threshold.Store(math.Float64bits(blockThresholdOf(cfg)))
}

// newReputationClient returns the client for an integration's provider type,
// or nil for a type this build does not know.
func newReputationClient(integration *gateonv1.IPReputationIntegration) ReputationClient {
	switch integration.GetType() {
	case "abuseipdb":
		return NewAbuseIPDBClient(integration.GetApiKey())
	case "virustotal":
		return NewVirusTotalClient(integration.GetApiKey())
	case "alienvault":
		return NewAlienVaultClient(integration.GetApiKey())
	}
	return nil
}

// cancelRefresh stops the refresh in flight, if there is one.
func (s *IPReputationStore) cancelRefresh() {
	s.cancelMu.Lock()
	defer s.cancelMu.Unlock()
	if s.refreshCancel != nil {
		s.refreshCancel()
	}
}

// trackRefresh records the cancel of the refresh now holding feedMu, or clears
// it when that refresh ends.
func (s *IPReputationStore) trackRefresh(cancel context.CancelFunc) {
	s.cancelMu.Lock()
	s.refreshCancel = cancel
	s.cancelMu.Unlock()
}

// feedsWanted reports whether cfg asks for any feed to be loaded.
func feedsWanted(cfg *gateonv1.IPReputationConfig) bool {
	return cfg != nil && cfg.Enabled && len(cfg.FeedUrls) > 0
}

// clearFeeds takes every feed entry out of force. It waits for a refresh
// already in flight, so that refresh cannot land its result afterwards.
func (s *IPReputationStore) clearFeeds() {
	s.feedMu.Lock()
	defer s.feedMu.Unlock()
	s.lastGood = nil
	s.index.Store(newFeedIndex())
	feedEntriesInForce.Set(0)
	feedIndexBytes.Set(0)
}

// IsBad reports whether a feed lists ipStr, and the score the listing carries.
// It takes no lock: an install with no feed entries pays one atomic load.
func (s *IPReputationStore) IsBad(ipStr string) (bool, float64) {
	idx := s.index.Load()
	if idx == nil || idx.entries == 0 {
		return false, 0
	}

	// A score set by SetIPScore, by the address as written.
	if score, ok := idx.ips[ipStr]; ok {
		return true, score
	}

	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false, 0
	}

	// A v4-mapped address is the IPv4 host it maps: the spelling a proxy on a
	// dual-stack socket writes for an IPv4 client. Searched as written it went
	// to the IPv6 entries, where no IPv4 entry lives, and every listed IPv4
	// address walked past the feed; contains unmaps it.
	if idx.ranges.contains(addr) {
		return true, feedListedScore
	}
	return false, 0
}

// Listed reports whether ipStr is listed at or above the block threshold:
// what "block known malicious actors" refuses.
func (s *IPReputationStore) Listed(ipStr string) bool {
	bad, score := s.IsBad(ipStr)
	return bad && score >= s.GetBlockThreshold()
}

// SetIPScore manually sets the reputation score for an IP (primarily for testing or internal overrides).
// The index is copied rather than written: a lookup may be reading it.
func (s *IPReputationStore) SetIPScore(ip string, score float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.index.Load()
	next := &feedIndex{ips: make(map[string]float64, len(old.ips)+1), ranges: old.ranges, entries: old.entries}
	for k, v := range old.ips {
		next.ips[k] = v
	}
	if _, dup := next.ips[ip]; !dup {
		next.entries++
	}
	next.ips[ip] = score
	s.index.Store(next)
}

// GetExternalScore checks external integrations for the given IP.
// It returns the highest confidence score found above its integration's
// threshold, and the name of the provider; (0, "") when no provider's answer
// clears its threshold.
//
// Each integration's "Confidence Threshold" -- "Score above which to consider
// IP malicious", the dashboard says -- used to be read by nothing: this
// returned the highest raw answer and the one consumer, the security threat
// detector, applied a hard-coded 20, so an operator who set 95 to cut noise or
// 10 to catch more changed nothing. The threshold is applied here now, per
// provider, and the detector takes whatever this returns.
func (s *IPReputationStore) GetExternalScore(ctx context.Context, ip string) (int, string) {
	s.mu.RLock()
	integrations := s.integrations
	s.mu.RUnlock()

	maxScore := 0
	bestProvider := ""

	for _, p := range integrations {
		if p.client != nil {
			score, err := p.client.CheckIP(ctx, ip)
			if err != nil {
				logger.L.LogWarn("failed to check IP in external provider", "provider", p.config.Name, "error", err)
				continue
			}
			if score > p.threshold() && score > maxScore {
				maxScore = score
				bestProvider = p.config.Name
			}
		}
	}

	return maxScore, bestProvider
}

// unsetExternalThreshold is the score a provider's answer must exceed when its
// integration has no threshold of its own: 0, proto3's unset, which is every
// integration saved before the field was read. It is the 20 the threat
// detector hard-coded, so those installs detect exactly what they did.
const unsetExternalThreshold = 20

// threshold is the score this provider's answer must exceed to count.
func (p reputationProvider) threshold() int {
	if t := int(p.config.GetConfidenceThreshold()); t > 0 {
		return t
	}
	return unsetExternalThreshold
}

func (s *IPReputationStore) GetBlockThreshold() float64 {
	if bits := s.threshold.Load(); bits != 0 {
		return math.Float64frombits(bits)
	}
	// Zero is a store built without configure; a configured threshold is
	// never zero (blockThresholdOf).
	return defaultBlockThreshold
}

// defaultBlockThreshold is the listing score that refuses when the config
// names none. A feed listing scores 100, so it refuses.
const defaultBlockThreshold = 80.0

func blockThresholdOf(cfg *gateonv1.IPReputationConfig) float64 {
	if t := cfg.GetBlockThreshold(); t > 0 {
		return t
	}
	return defaultBlockThreshold
}

// Start loads the configured feeds, then keeps them refreshed until ctx ends.
//
// The refresh loop runs whether or not IP reputation is enabled at boot. It
// used to be built only when it was, from the interval in force at that moment,
// so feeds switched on later from the dashboard -- the ordinary path, since the
// stock configuration ships with IP reputation off -- were loaded once by the
// save and never again, and a changed interval never took effect. The loop now
// reads the interval every time it waits, and Reconfigure moves it onto a new
// one.
func (s *IPReputationStore) Start(ctx context.Context) {
	s.update(ctx)
	s.loopOnce.Do(func() {
		// Armed here rather than in the goroutine, so the first wait is the
		// interval configured when Start ran, not whatever a Reconfigure that
		// raced the goroutine's start left behind.
		timer := time.NewTimer(s.refreshInterval())
		s.loopDone = make(chan struct{})
		go s.refreshLoop(ctx, timer)
	})
}

// Wait blocks until the refresh loop Start began has returned, which it does
// once Start's context ends; it returns at once when Start never ran. It is
// how a caller that cancels the context joins the loop rather than leaving it
// running behind it.
func (s *IPReputationStore) Wait() {
	if s.loopDone != nil {
		<-s.loopDone
	}
}

// refreshLoop refreshes the feeds each time timer fires until ctx ends. A store
// with no feed wanted costs one timer: update returns at once.
func (s *IPReputationStore) refreshLoop(ctx context.Context, timer *time.Timer) {
	defer close(s.loopDone)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.rescheduled:
			// Reconfigure has already refreshed for the new configuration;
			// only the schedule moves onto it.
		case <-timer.C:
			s.update(ctx)
		}
		timer.Reset(s.refreshInterval())
	}
}

// refreshInterval is the configured update interval as a timer period.
func (s *IPReputationStore) refreshInterval() time.Duration {
	s.mu.RLock()
	hours := s.config.GetUpdateIntervalHours()
	s.mu.RUnlock()
	return updateInterval(hours)
}

// reschedule tells the refresh loop the configuration changed. It never
// blocks: one pending signal is as good as several.
func (s *IPReputationStore) reschedule() {
	select {
	case s.rescheduled <- struct{}{}:
	default:
	}
}

// feedFetchTimeout bounds one feed fetch, body included.
//
// Feeds were fetched with http.DefaultClient, which has no timeout, so a
// provider that accepted the connection and never answered held the refresh
// for as long as it kept the socket open -- and Start runs that refresh before
// the gateway opens a listener. Thirty seconds is generous for a plain-text
// list and short enough that a stuck provider delays a boot rather than
// preventing it. A variable so a test does not have to wait it out.
var feedFetchTimeout = 30 * time.Second

// Feed refresh period, in hours, when update_interval_hours is unset, and the
// most it may be set to: a larger value wraps time.Duration.
const (
	defaultUpdateIntervalHours = 24
	maxUpdateIntervalHours     = 24 * 365
)

// refreshUnit is the length of one update_interval_hours: an hour. A variable so
// a test can run a schedule measured in hours in milliseconds.
var refreshUnit = time.Hour

// updateInterval turns update_interval_hours into a timer period.
//
// A timer or ticker panics on anything but a positive duration, and Start runs
// synchronously at boot. The hours used to be converted and handed to it before
// anything looked at them, so zero -- what an operator gets by enabling IP
// reputation without touching the interval -- crashed the gateway on every
// start, as did a negative value or one large enough to wrap negative.
func updateInterval(hours int32) time.Duration {
	switch {
	case hours == 0:
		hours = defaultUpdateIntervalHours
	case hours < 0:
		logger.L.LogWarn("ip_reputation.update_interval_hours is negative; using the default",
			"configured", hours, "default_hours", defaultUpdateIntervalHours)
		hours = defaultUpdateIntervalHours
	case hours > maxUpdateIntervalHours:
		logger.L.LogWarn("ip_reputation.update_interval_hours is above the maximum; using the maximum",
			"configured", hours, "max_hours", maxUpdateIntervalHours)
		hours = maxUpdateIntervalHours
	}
	return time.Duration(hours) * refreshUnit
}

// update refreshes the blocklist from every configured feed.
//
// A feed that cannot be read keeps the entries it gave last time. This used to
// build the new set from whatever arrived and swap it in unconditionally, so a
// feed that was unreachable at refresh time -- or that answered with an error
// page, which parses as zero addresses -- replaced a full blocklist with an
// empty one until the next refresh, 24 hours later by default. A provider's
// rate limit or a moment's outage was enough to take every listed address out
// of force, with nothing but a log line to say so.
func (s *IPReputationStore) update(ctx context.Context) {
	// One refresh at a time: the ticker and Reconfigure can both start one.
	s.feedMu.Lock()
	defer s.feedMu.Unlock()

	// Cancellable by Reconfigure, which replaces the configuration this refresh
	// is fetching for and, when switching feeds off, waits for it to finish.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.trackRefresh(cancel)
	defer s.trackRefresh(nil)

	// Read under feedMu, so a refresh cannot act on a configuration that a
	// Reconfigure has already replaced and cleared behind it.
	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()
	if !feedsWanted(cfg) {
		return
	}

	current, ok := s.loadFeeds(ctx, cfg.FeedUrls, currentFeedLimits())
	if !ok {
		// Superseded or shut down: what this refresh read is for a
		// configuration that is gone, so it installs none of it.
		return
	}
	// Replacing the map also drops the copies of feeds no longer configured,
	// which is what bounds it. The old index and copies are garbage once the
	// new index is stored: a refresh holds at most two generations, each
	// within the limits.
	s.lastGood = current
	idx := indexFeeds(cfg.FeedUrls, current)
	s.index.Store(idx)
	held := heldBytes(idx, current)
	feedEntriesInForce.Set(float64(idx.entries))
	feedIndexBytes.Set(float64(held))

	logger.L.LogInfo("IP reputation store updated; listed addresses are refused on every entrypoint",
		"entries", idx.entries, "bytes", held)
}

// heldBytes is what the feeds hold in memory: the index, and -- when there is
// more than one feed, so the index is a merged copy -- each feed's last good
// copy beside it. One feed's copy is the index's own ranges.
func heldBytes(idx *feedIndex, feeds map[string]*feedLoad) int64 {
	n := idx.ranges.bytes()
	if len(feeds) < 2 {
		return n
	}
	for _, f := range feeds {
		n += f.ranges.bytes()
	}
	return n
}

// loadFeeds reads every feed in turn, within limits, and reports false when
// ctx ended first. A feed that cannot be read keeps its last good copy, which
// draws on the limits like a fresh one.
func (s *IPReputationStore) loadFeeds(ctx context.Context, urls []string, limits feedLimits) (map[string]*feedLoad, bool) {
	// The index's top lookup tables are held beside the ranges; the byte bound
	// covers them, so the ranges get what is left.
	budget := feedBudget{entries: limits.entries, bytes: max(limits.bytes-topIndexBytes, 0)}
	current := make(map[string]*feedLoad, len(urls))
	for _, url := range urls {
		if _, dup := current[url]; dup {
			continue
		}
		load, err := fetchFeed(ctx, url, &budget)
		if ctx.Err() != nil {
			return nil, false
		}
		if err != nil {
			load = s.keepLastGood(url, err, &budget)
		}
		if load != nil {
			reportRefused(url, load, limits)
			current[url] = load
		}
	}
	return current, true
}

// keepLastGood is url's last good copy, when the budget still has room for
// it, for a feed that could not be read.
func (s *IPReputationStore) keepLastGood(url string, err error, budget *feedBudget) *feedLoad {
	prev := s.lastGood[url]
	if prev == nil {
		logger.L.LogError("failed to fetch IP reputation feed; it has no earlier copy, so none of it is in force",
			"error", err, "url", url)
		return nil
	}
	if prev.entries > budget.entries || prev.bytes > budget.bytes {
		feedEntriesRefused.WithLabelValues(refusedOverLimit).Add(float64(prev.entries))
		logger.L.LogError("failed to fetch IP reputation feed, and its last good copy no longer fits the "+
			"feed limits; none of it is in force", "error", err, "url", url, "entries", prev.entries,
			"env", feedMaxEntriesEnv+", "+feedMaxMBEnv)
		return nil
	}
	budget.entries -= prev.entries
	budget.bytes -= prev.bytes
	logger.L.LogError("failed to fetch IP reputation feed; its last good copy stays in force",
		"error", err, "url", url, "entries_kept", prev.entries)
	// Counted once, when it was read; the copy carries no refusals of its own.
	return &feedLoad{ranges: prev.ranges, entries: prev.entries, bytes: prev.bytes}
}

// reportRefused counts and logs, at ERROR, the entries of one feed that are
// not in force: listed addresses the gateway will not refuse.
func reportRefused(url string, load *feedLoad, limits feedLimits) {
	if load.tooWide > 0 {
		feedEntriesRefused.WithLabelValues(refusedTooWide).Add(float64(load.tooWide))
		logger.L.LogError("IP reputation feed lists prefixes wider than a feed entry may be; they are not in force",
			"url", url, "entries", load.tooWide, "first", load.widest,
			"widest_allowed", fmt.Sprintf("IPv4 /%d, IPv6 /%d", minFeedBitsV4, minFeedBitsV6))
	}
	if load.overLimit > 0 {
		feedEntriesRefused.WithLabelValues(refusedOverLimit).Add(float64(load.overLimit))
		logger.L.LogError("IP reputation feeds list more than the feed limits hold; the entries past them are not in force",
			"url", url, "entries_refused", load.overLimit, "max_entries", limits.entries,
			"max_bytes", limits.bytes, "env", feedMaxEntriesEnv+", "+feedMaxMBEnv)
	}
}

// indexFeeds builds the index from every feed's entries, in configured order.
func indexFeeds(urls []string, feeds map[string]*feedLoad) *feedIndex {
	sets := make([]feedRanges, 0, len(feeds))
	seen := make(map[string]bool, len(feeds))
	idx := newFeedIndex()
	for _, url := range urls {
		if load, ok := feeds[url]; ok && !seen[url] {
			seen[url] = true
			sets = append(sets, load.ranges)
			idx.entries += load.entries
		}
	}
	idx.ranges = unionRanges(sets)
	return idx
}

// feedListedScore is the score an address carries for appearing on a feed.
//
// A plain-text feed says one thing about an address -- refuse it -- so a listing
// is the top of the 0-100 scale that GetBlockThreshold is expressed in. It used
// to be 1.0, which sat below the default threshold of 80 and below the 80 the
// dashboard recommends, so the WAF's feed rule could not fire and a feed that
// loaded thousands of addresses blocked none of them. An operator who wants a
// feed recorded but not enforced sets the threshold above 100.
const feedListedScore = 100.0
