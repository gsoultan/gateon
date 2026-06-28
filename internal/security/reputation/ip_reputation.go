package reputation

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type IPReputationStore struct {
	mu           sync.RWMutex
	badIPs       map[string]float64
	badNets      []*net.IPNet
	config       *gateonv1.IPReputationConfig
	integrations []reputationProvider
}

type reputationProvider struct {
	config *gateonv1.IPReputationIntegration
	client *AbuseIPDBClient // For now, only AbuseIPDB is supported
}

func NewIPReputationStore(cfg *gateonv1.IPReputationConfig) *IPReputationStore {
	store := &IPReputationStore{
		badIPs: make(map[string]float64),
		config: cfg,
	}

	if cfg != nil {
		for _, integration := range cfg.Integrations {
			if integration.Enabled && integration.Type == "abuseipdb" {
				store.integrations = append(store.integrations, reputationProvider{
					config: integration,
					client: NewAbuseIPDBClient(integration.ApiKey),
				})
			}
		}
	}

	return store
}

func (s *IPReputationStore) IsBad(ipStr string) (bool, float64) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if score, ok := s.badIPs[ipStr]; ok {
		return true, score
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, 0
	}

	for _, n := range s.badNets {
		if n.Contains(ip) {
			return true, 1.0
		}
	}

	return false, 0
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
	var newNets []*net.IPNet

	for _, url := range s.config.FeedUrls {
		if err := s.fetchFeed(ctx, url, newIPs, &newNets); err != nil {
			logger.L.LogError("failed to fetch IP reputation feed", "error", err, "url", url)
		}
	}

	s.mu.Lock()
	s.badIPs = newIPs
	s.badNets = newNets
	s.mu.Unlock()

	logger.L.Info().Int("ips", len(newIPs)).Int("nets", len(newNets)).Msg("IP reputation store updated")
}

func (s *IPReputationStore) fetchFeed(ctx context.Context, url string, ips map[string]float64, nets *[]*net.IPNet) error {
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
			_, ipnet, err := net.ParseCIDR(line)
			if err == nil {
				*nets = append(*nets, ipnet)
			}
		} else {
			ips[line] = 1.0
		}
	}

	return scanner.Err()
}
