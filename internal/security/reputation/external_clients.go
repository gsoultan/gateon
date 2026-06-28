package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/gsoultan/gateon/internal/logger"
)

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
	cache   sync.Map
}

func NewAbuseIPDBClient(apiKey string) *AbuseIPDBClient {
	return &AbuseIPDBClient{
		APIKey:  apiKey,
		BaseURL: "https://api.abuseipdb.com/api/v2/check",
	}
}

func (c *AbuseIPDBClient) CheckIP(ctx context.Context, ip string) (int, error) {
	if c.APIKey == "" {
		return 0, nil
	}

	if val, ok := c.cache.Load(ip); ok {
		if score, ok := val.(int); ok {
			return score, nil
		}
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

	resp, err := http.DefaultClient.Do(req)
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
	c.cache.Store(ip, score)

	return score, nil
}

// VirusTotalClient implements ReputationClient for VirusTotal API v3.
type VirusTotalClient struct {
	APIKey  string
	BaseURL string
	cache   sync.Map
}

func NewVirusTotalClient(apiKey string) *VirusTotalClient {
	return &VirusTotalClient{
		APIKey:  apiKey,
		BaseURL: "https://www.virustotal.com/api/v3/ip_addresses/",
	}
}

func (c *VirusTotalClient) CheckIP(ctx context.Context, ip string) (int, error) {
	if c.APIKey == "" {
		return 0, nil
	}

	if val, ok := c.cache.Load(ip); ok {
		return val.(int), nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+ip, nil)
	if err != nil {
		return 0, err
	}

	req.Header.Set("x-apikey", c.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
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

	c.cache.Store(ip, score)
	return score, nil
}

// AlienVaultClient implements ReputationClient for AlienVault OTX.
type AlienVaultClient struct {
	APIKey  string
	BaseURL string
	cache   sync.Map
}

func NewAlienVaultClient(apiKey string) *AlienVaultClient {
	return &AlienVaultClient{
		APIKey:  apiKey,
		BaseURL: "https://otx.alienvault.com/api/v1/indicators/IPv4/",
	}
}

func (c *AlienVaultClient) CheckIP(ctx context.Context, ip string) (int, error) {
	if c.APIKey == "" {
		return 0, nil
	}

	if val, ok := c.cache.Load(ip); ok {
		return val.(int), nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+ip+"/general", nil)
	if err != nil {
		return 0, err
	}

	if c.APIKey != "" {
		req.Header.Set("X-OTX-API-KEY", c.APIKey)
	}

	resp, err := http.DefaultClient.Do(req)
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

	c.cache.Store(ip, score)
	return score, nil
}
