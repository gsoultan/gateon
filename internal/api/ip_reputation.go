package api

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
	mu      sync.RWMutex
	badIPs  map[string]float64
	badNets []*net.IPNet
	config  *gateonv1.IPReputationConfig
}

func NewIPReputationStore(cfg *gateonv1.IPReputationConfig) *IPReputationStore {
	return &IPReputationStore{
		badIPs: make(map[string]float64),
		config: cfg,
	}
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
