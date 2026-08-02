// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package reputation

import (
	"bufio"
	"context"
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

func NewIPReputationStore(cfg *gateonv1.IPReputationConfig) *IPReputationStore {
	store := &IPReputationStore{
		badIPs: make(map[string]float64),
		trie:   newIPTrie(),
	}
	store.Reconfigure(cfg)
	return store
}

// Reconfigure updates the store configuration and re-initializes integrations.
func (s *IPReputationStore) Reconfigure(cfg *gateonv1.IPReputationConfig) {
	s.mu.Lock()
	s.config = cfg
	s.integrations = nil
	if cfg != nil {
		for _, integration := range cfg.Integrations {
			if !integration.Enabled {
				continue
			}
			switch integration.Type {
			case "abuseipdb":
				s.integrations = append(s.integrations, reputationProvider{
					config: integration,
					client: NewAbuseIPDBClient(integration.ApiKey),
				})
			case "virustotal":
				s.integrations = append(s.integrations, reputationProvider{
					config: integration,
					client: NewVirusTotalClient(integration.ApiKey),
				})
			case "alienvault":
				s.integrations = append(s.integrations, reputationProvider{
					config: integration,
					client: NewAlienVaultClient(integration.ApiKey),
				})
			}
		}
	}
	s.mu.Unlock()

	if cfg != nil && cfg.Enabled {
		// Trigger an update in background to pick up new feed URLs immediately
		go s.update(context.Background())
	}
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

	return s.trie.search(addr)
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

func (s *IPReputationStore) Start(ctx context.Context) {
	if s.config == nil || !s.config.Enabled {
		return
	}

	ticker := time.NewTicker(time.Duration(s.config.UpdateIntervalHours) * time.Hour)
	if s.config.UpdateIntervalHours == 0 {
		ticker = time.NewTicker(24 * time.Hour)
	}

	s.update(ctx)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.update(ctx)
			}
		}
	}()
}

func (s *IPReputationStore) update(ctx context.Context) {
	if s.config == nil || len(s.config.FeedUrls) == 0 {
		return
	}

	newIPs := make(map[string]float64)
	newTrie := newIPTrie()

	for _, url := range s.config.FeedUrls {
		if err := s.fetchFeed(ctx, url, newIPs, newTrie); err != nil {
			logger.L.LogError("failed to fetch IP reputation feed", "error", err, "url", url)
		}
	}

	s.mu.Lock()
	s.badIPs = newIPs
	s.trie = newTrie
	s.mu.Unlock()

	logger.L.Info().Int("ips", len(newIPs)).Msg("IP reputation store updated with Radix Tree")
}

func (s *IPReputationStore) fetchFeed(ctx context.Context, url string, ips map[string]float64, trie *ipTrie) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle comments at the end of the line
		if idx := strings.Index(line, "#"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}

		if strings.Contains(line, "/") {
			prefix, err := netip.ParsePrefix(line)
			if err == nil {
				trie.insert(prefix, 1.0)
			}
		} else {
			addr, err := netip.ParseAddr(line)
			if err == nil {
				// We can also insert single IPs into the trie for unified fast lookup,
				// but map is even faster for exact match. Let's do both or just trie.
				// Trie handles both fine and is O(bits).
				trie.insert(netip.PrefixFrom(addr, addr.BitLen()), 1.0)
				ips[line] = 1.0
			}
		}
	}

	return scanner.Err()
}
