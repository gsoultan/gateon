package api

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
	APIKey string
	cache  sync.Map
}

func NewAbuseIPDBClient(apiKey string) *AbuseIPDBClient {
	return &AbuseIPDBClient{APIKey: apiKey}
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

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.abuseipdb.com/api/v2/check", nil)
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
			logger.L.Warn().Msg("AbuseIPDB rate limit exceeded")
		}
		return 0, fmt.Errorf("AbuseIPDB returned status %d", resp.StatusCode)
	}

	var result AbuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}

	score := result.Data.AbuseConfidenceScore
	c.cache.Store(ip, score)

	// Cache expiration would be good here, but sync.Map doesn't support it easily.
	// For this implementation, we just store it.

	return score, nil
}
