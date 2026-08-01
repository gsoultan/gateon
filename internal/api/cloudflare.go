package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func (s *ApiService) GetCloudflareIPs(ctx context.Context, _ *gateonv1.GetCloudflareIPsRequest) (*gateonv1.GetCloudflareIPsResponse, error) {
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.cloudflare.com/client/v4/ips")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch cloudflare ips: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cloudflare api returned status: %d", resp.StatusCode)
	}

	var cfResp struct {
		Result struct {
			IPv4CIDRs []string `json:"ipv4_cidrs"`
			IPv6CIDRs []string `json:"ipv6_cidrs"`
		} `json:"result"`
		Success bool `json:"success"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		return nil, fmt.Errorf("failed to decode cloudflare response: %w", err)
	}

	if !cfResp.Success {
		return nil, errors.New("cloudflare api reported failure")
	}

	return &gateonv1.GetCloudflareIPsResponse{
		Ipv4Cidrs: cfResp.Result.IPv4CIDRs,
		Ipv6Cidrs: cfResp.Result.IPv6CIDRs,
	}, nil
}

var (
	publicIPCache   string
	lastIPFetch     time.Time
	publicIPCacheMu sync.RWMutex
)

const publicIPCacheTTL = 1 * time.Hour

func getPublicIP(ctx context.Context) string {
	publicIPCacheMu.RLock()
	if publicIPCache != "" && time.Since(lastIPFetch) < publicIPCacheTTL {
		ip := publicIPCache
		publicIPCacheMu.RUnlock()
		return ip
	}
	publicIPCacheMu.RUnlock()

	publicIPCacheMu.Lock()
	defer publicIPCacheMu.Unlock()

	// Double check after acquiring lock
	if publicIPCache != "" && time.Since(lastIPFetch) < publicIPCacheTTL {
		return publicIPCache
	}

	providers := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://ipinfo.io/ip",
		"https://ident.me",
		"https://v4.ident.me",
	}

	// Use a slightly longer timeout for the whole process but keep individual attempts short
	client := http.Client{Timeout: 3 * time.Second}
	for _, url := range providers {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			logger.Default().LogWarn("Public IP detection failed for provider", "url", url, "error", err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		if resp.StatusCode != http.StatusOK {
			logger.Default().LogWarn("Public IP provider returned non-200 status", "url", url, "status", resp.StatusCode)
			continue
		}

		ipStr := string(bytes.TrimSpace(body))
		if net.ParseIP(ipStr) != nil {
			publicIPCache = ipStr
			lastIPFetch = time.Now()
			return ipStr
		}
	}

	logger.Default().LogError("All Public IP providers failed", "count", len(providers))
	publicIPCache = "unknown"
	lastIPFetch = time.Now()
	return "unknown"
}

func isCloudflareReachable() (bool, time.Duration) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", "1.1.1.1:53", 2*time.Second)
	if err != nil {
		return false, 0
	}
	defer conn.Close()
	return true, time.Since(start)
}
