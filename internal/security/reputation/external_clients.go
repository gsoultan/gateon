// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	lru "github.com/hashicorp/golang-lru"

	"github.com/gsoultan/gateon/internal/logger"
)

const (
	// externalScoreCacheSize bounds each provider's cache.
	//
	// The key is the client's IP, so the set of entries is exactly the set of
	// addresses attacking the gateway: the cache grew fastest under the
	// conditions it most needed to survive, and an attacker rotating source
	// addresses -- trivial over IPv6 -- grew it without limit. It was a bare
	// sync.Map with no eviction at all.
	//
	// 4096 per provider at roughly 64 bytes an entry is about 256 KB, which the
	// 2-core/2 GB target can hold three times over.
	externalScoreCacheSize = 4096

	// externalScoreTTL is how long a provider's answer is reused.
	//
	// This is the half that mattered. The answer used to be pinned for the life
	// of the process, so an address that was clean the first time it was seen
	// stayed clean in this gateway's view no matter what it did afterwards --
	// external threat intelligence reduced to a first-contact snapshot. The
	// AbuseIPDB request even carries maxAgeInDays=90, asking the API for fresh
	// data, and then the freshness was discarded locally.
	//
	// An hour is short enough that a newly-listed address is picked up within
	// one, and long enough to stay inside AbuseIPDB's free-tier daily quota
	// under any traffic this cache sees.
	externalScoreTTL = time.Hour

	// externalRequestTimeout bounds a provider call. http.DefaultClient has no
	// timeout, so before this a provider that accepted a connection and never
	// answered held the analyser for as long as the caller's context allowed.
	externalRequestTimeout = 10 * time.Second
)

// externalHTTPClient is shared by the providers so connections are pooled
// across lookups, and carries the timeout http.DefaultClient does not.
var externalHTTPClient = &http.Client{Timeout: externalRequestTimeout}

// cachedScore pairs a provider's answer with when it was taken, so a bounded
// cache cannot also be a permanent one.
type cachedScore struct {
	score     int
	fetchedAt time.Time
}

// scoreCache is a bounded, expiring cache of provider answers, replacing a
// sync.Map that was neither.
type scoreCache struct {
	lru *lru.Cache
	ttl time.Duration
}

func newScoreCache() *scoreCache { return newScoreCacheWithTTL(externalScoreTTL) }

func newScoreCacheWithTTL(ttl time.Duration) *scoreCache {
	// lru.New only errors on a non-positive size, and the size is a constant
	// here. A nil cache still behaves correctly -- every lookup misses -- so
	// this degrades to "no caching" rather than to a panic at startup.
	c, err := lru.New(externalScoreCacheSize)
	if err != nil {
		logger.L.LogError("reputation: external score cache disabled", "error", err)
		return &scoreCache{ttl: ttl}
	}
	return &scoreCache{lru: c, ttl: ttl}
}

// get returns a cached score that is still fresh.
func (s *scoreCache) get(ip string) (int, bool) {
	if s == nil || s.lru == nil {
		return 0, false
	}
	v, ok := s.lru.Get(ip)
	if !ok {
		return 0, false
	}
	// Comma-ok rather than a bare assertion: two of the three providers used
	// val.(int) directly, which panics on the analyser's goroutine if the cache
	// ever holds anything else. Treating an unexpected value as a miss costs
	// one lookup.
	e, isEntry := v.(cachedScore)
	if !isEntry {
		s.lru.Remove(ip)
		return 0, false
	}
	if time.Since(e.fetchedAt) >= s.ttl {
		s.lru.Remove(ip)
		return 0, false
	}
	return e.score, true
}

func (s *scoreCache) put(ip string, score int) {
	if s == nil || s.lru == nil {
		return
	}
	s.lru.Add(ip, cachedScore{score: score, fetchedAt: time.Now()})
}

type AbuseIPDBResponse struct {
	Data struct {
		IPAddress            string   `json:"ipAddress"`
		IsPublic             bool     `json:"isPublic"`
		IpVersion            int      `json:"ipVersion"`
		IsWhitelisted        bool     `json:"isWhitelisted"`
		AbuseConfidenceScore int      `json:"abuseConfidenceScore"`
		CountryCode          string   `json:"countryCode"`
		UsageType            string   `json:"usageType"`
		Isp                  string   `json:"isp"`
		Domain               string   `json:"domain"`
		Hostnames            []string `json:"hostnames"`
		TotalReports         int      `json:"totalReports"`
		NumDistinctUsers     int      `json:"numDistinctUsers"`
		LastReportedAt       string   `json:"lastReportedAt"`
	} `json:"data"`
}

type AbuseIPDBClient struct {
	APIKey  string
	BaseURL string
	cache   *scoreCache
}

func NewAbuseIPDBClient(apiKey string) *AbuseIPDBClient {
	return &AbuseIPDBClient{
		APIKey:  apiKey,
		cache:   newScoreCache(),
		BaseURL: "https://api.abuseipdb.com/api/v2/check",
	}
}

func (c *AbuseIPDBClient) CheckIP(ctx context.Context, ip string) (int, error) {
	if c.APIKey == "" {
		return 0, nil
	}

	if score, ok := c.cache.get(ip); ok {
		return score, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL, nil)
	if err != nil {
		return 0, err
	}

	q := req.URL.Query()
	q.Add("ipAddress", ip)
	q.Add("maxAgeInDays", "90")
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Key", c.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := externalHTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == 429 {
			logger.L.LogWarn("AbuseIPDB rate limit exceeded")
		}
		return 0, fmt.Errorf("AbuseIPDB returned status %d", resp.StatusCode)
	}

	var result AbuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}

	score := result.Data.AbuseConfidenceScore
	c.cache.put(ip, score)

	return score, nil
}

// VirusTotalClient implements ReputationClient for VirusTotal API v3.
type VirusTotalClient struct {
	APIKey  string
	BaseURL string
	cache   *scoreCache
}

func NewVirusTotalClient(apiKey string) *VirusTotalClient {
	return &VirusTotalClient{
		APIKey:  apiKey,
		cache:   newScoreCache(),
		BaseURL: "https://www.virustotal.com/api/v3/ip_addresses/",
	}
}

func (c *VirusTotalClient) CheckIP(ctx context.Context, ip string) (int, error) {
	if c.APIKey == "" {
		return 0, nil
	}

	if score, ok := c.cache.get(ip); ok {
		return score, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+ip, nil)
	if err != nil {
		return 0, err
	}

	req.Header.Set("x-apikey", c.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := externalHTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("VirusTotal returned status %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious int `json:"malicious"`
					Harmless  int `json:"harmless"`
				} `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}

	// Simple heuristic: percentage of malicious engines (max 100)
	stats := result.Data.Attributes.LastAnalysisStats
	total := stats.Malicious + stats.Harmless
	score := 0
	if total > 0 {
		score = (stats.Malicious * 100) / total
	}
	if stats.Malicious > 0 && score < 10 {
		score = 10 // Minimum score if at least one engine says malicious
	}

	c.cache.put(ip, score)
	return score, nil
}

// AlienVaultClient implements ReputationClient for AlienVault OTX.
type AlienVaultClient struct {
	APIKey  string
	BaseURL string
	cache   *scoreCache
}

func NewAlienVaultClient(apiKey string) *AlienVaultClient {
	return &AlienVaultClient{
		APIKey:  apiKey,
		cache:   newScoreCache(),
		BaseURL: "https://otx.alienvault.com/api/v1/indicators/IPv4/",
	}
}

func (c *AlienVaultClient) CheckIP(ctx context.Context, ip string) (int, error) {
	if c.APIKey == "" {
		return 0, nil
	}

	if score, ok := c.cache.get(ip); ok {
		return score, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+ip+"/general", nil)
	if err != nil {
		return 0, err
	}

	if c.APIKey != "" {
		req.Header.Set("X-OTX-API-KEY", c.APIKey)
	}

	resp, err := externalHTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("AlienVault returned status %d", resp.StatusCode)
	}

	var result struct {
		PulseInfo struct {
			Count int `json:"count"`
		} `json:"pulse_info"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}

	// Heuristic: scale based on number of pulses (max 100)
	score := result.PulseInfo.Count * 10
	if score > 100 {
		score = 100
	}

	c.cache.put(ip, score)
	return score, nil
}
