// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package reputation

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type IPReputationStore struct {
	mu           sync.RWMutex
	trie         *ipTrie
	badIPs       map[string]float64
	config       *gateonv1.IPReputationConfig
	integrations []reputationProvider

	// feedMu serialises refreshes and guards lastGood.
	feedMu sync.Mutex
	// lastGood is what each configured feed said the last time it could be
	// read, keyed by URL, so a feed that fails at refresh time keeps its
	// entries in force. Only configured feeds are kept.
	lastGood map[string][]netip.Prefix

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

type trieNode struct {
	children [2]*trieNode
	score    float64
	hasValue bool
}

type ipTrie struct {
	v4 *trieNode
	v6 *trieNode
}

func newIPTrie() *ipTrie {
	return &ipTrie{
		v4: &trieNode{},
		v6: &trieNode{},
	}
}

func (t *ipTrie) insert(prefix netip.Prefix, score float64) {
	addr := prefix.Addr()
	ones := prefix.Bits()
	var curr *trieNode
	var bits []byte

	if addr.Is4() {
		curr = t.v4
		b := addr.As4()
		bits = b[:]
	} else {
		curr = t.v6
		b := addr.As16()
		bits = b[:]
	}

	for i := 0; i < ones; i++ {
		bit := (bits[i/8] >> (7 - (uint(i) % 8))) & 1
		if curr.children[bit] == nil {
			curr.children[bit] = &trieNode{}
		}
		curr = curr.children[bit]
	}
	// Longest prefix match wins for score if we just overwrite,
	// but we could also take the max.
	if score > curr.score || !curr.hasValue {
		curr.score = score
	}
	curr.hasValue = true
}

func (t *ipTrie) search(addr netip.Addr) (bool, float64) {
	var curr *trieNode
	var bits []byte
	var maxBits int

	if addr.Is4() {
		curr = t.v4
		b := addr.As4()
		bits = b[:]
		maxBits = 32
	} else {
		curr = t.v6
		b := addr.As16()
		bits = b[:]
		maxBits = 128
	}

	var lastScore float64
	var found bool

	if curr.hasValue {
		lastScore = curr.score
		found = true
	}

	for i := 0; i < maxBits; i++ {
		bit := (bits[i/8] >> (7 - (uint(i) % 8))) & 1
		if curr.children[bit] == nil {
			break
		}
		curr = curr.children[bit]
		if curr.hasValue {
			lastScore = curr.score
			found = true
		}
	}

	return found, lastScore
}

// NewIPReputationStore builds a store for cfg. It loads nothing: Start does the
// first load.
//
// It used to go through Reconfigure, which starts a background refresh, and
// both callers then call Start, which refreshes again and waits for the first
// to finish -- so every boot fetched every feed twice, one after the other,
// before a listener opened.
func NewIPReputationStore(cfg *gateonv1.IPReputationConfig) *IPReputationStore {
	store := &IPReputationStore{
		badIPs:      make(map[string]float64),
		trie:        newIPTrie(),
		rescheduled: make(chan struct{}, 1),
	}
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
	s.mu.Lock()
	s.badIPs = make(map[string]float64)
	s.trie = newIPTrie()
	s.mu.Unlock()
}

func (s *IPReputationStore) IsBad(ipStr string) (bool, float64) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check manual map first (O(1))
	if score, ok := s.badIPs[ipStr]; ok {
		return true, score
	}

	// Fast lookup in Radix Tree (O(bits))
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false, 0
	}

	// A v4-mapped address is the IPv4 host it maps: the spelling a proxy on a
	// dual-stack socket writes for an IPv4 client. Searched as written it went
	// to the IPv6 trie, where no IPv4 entry lives, and every listed IPv4
	// address walked past the feed. The trie holds every entry, host routes
	// included, so the unmapped search finds what the map lookup above missed.
	return s.trie.search(addr.Unmap())
}

// SetIPScore manually sets the reputation score for an IP (primarily for testing or internal overrides).
func (s *IPReputationStore) SetIPScore(ip string, score float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.badIPs == nil {
		s.badIPs = make(map[string]float64)
	}
	s.badIPs[ip] = score
}

// GetExternalScore checks external integrations for the given IP.
// It returns the highest confidence score found and the name of the provider.
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
			if score > maxScore {
				maxScore = score
				bestProvider = p.config.Name
			}
		}
	}

	return maxScore, bestProvider
}

func (s *IPReputationStore) GetBlockThreshold() float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.config != nil && s.config.BlockThreshold > 0 {
		return s.config.BlockThreshold
	}
	return 80.0 // Default
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

	current := make(map[string][]netip.Prefix, len(cfg.FeedUrls))
	for _, url := range cfg.FeedUrls {
		prefixes, err := fetchFeed(ctx, url)
		if ctx.Err() != nil {
			// Superseded or shut down: what this refresh read is for a
			// configuration that is gone, so it installs none of it.
			return
		}
		if err != nil {
			prefixes = s.lastGood[url]
			logger.L.LogError("failed to fetch IP reputation feed; its last good copy stays in force",
				"error", err, "url", url, "entries_kept", len(prefixes))
		}
		current[url] = prefixes
	}
	// Replacing the map also drops the copies of feeds no longer configured,
	// which is what bounds it.
	s.lastGood = current

	newIPs, newTrie := indexFeeds(current)
	s.mu.Lock()
	s.badIPs = newIPs
	s.trie = newTrie
	s.mu.Unlock()

	logger.L.Info().Int("ips", len(newIPs)).Msg("IP reputation store updated with Radix Tree")
}

// indexFeeds builds the lookup structures from every feed's entries.
func indexFeeds(feeds map[string][]netip.Prefix) (map[string]float64, *ipTrie) {
	ips := make(map[string]float64)
	trie := newIPTrie()
	for _, prefixes := range feeds {
		for _, p := range prefixes {
			trie.insert(p, feedListedScore)
			if p.IsSingleIP() {
				ips[p.Addr().String()] = feedListedScore
			}
		}
	}
	return ips, trie
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

// fetchFeed reads one plain-text feed: an address or CIDR per line, with "#"
// comments.
//
// Anything but a 2xx answer is an error. An error page is not an empty feed:
// its body parses as zero addresses, and taking that as the feed's answer would
// take every entry out of force.
func fetchFeed(ctx context.Context, url string) ([]netip.Prefix, error) {
	// The deadline covers the body as well as the headers: the scan below
	// reads through the same request context.
	ctx, cancel := context.WithTimeout(ctx, feedFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("feed answered with status %d", resp.StatusCode)
	}

	var out []netip.Prefix
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		if p, ok := parseFeedLine(scanner.Text()); ok {
			out = append(out, p)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
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
