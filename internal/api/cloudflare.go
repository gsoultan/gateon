package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

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

func getPublicIP() string {
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return "unknown"
	}
	defer resp.Body.Close()
	ip, _ := io.ReadAll(resp.Body)
	return string(ip)
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
