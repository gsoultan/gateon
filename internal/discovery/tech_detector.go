package discovery

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	gtls "github.com/gsoultan/gateon/internal/tls"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TechDetector probes a backend service to identify its technology stack and provide configuration recommendations.
type TechDetector struct{}

// Discover probes the given URL and returns identified technology and recommendations.
func (d *TechDetector) Discover(ctx context.Context, targetURL string, tlsConfig *gateonv1.TlsClientConfig) (*gateonv1.DiscoverTechResponse, error) {
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + targetURL
	}

	// SSRF prevention: validate host
	if os.Getenv("GATEON_TEST") != "1" {
		u, err := net.LookupHost(extractHost(targetURL))
		if err == nil {
			for _, ip := range u {
				if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
					return nil, fmt.Errorf("access to localhost is forbidden")
				}
			}
		}
	}

	var tlsClientCfg *tls.Config
	if strings.HasPrefix(targetURL, "https://") {
		tlsClientCfg, _ = gtls.CreateTLSClientConfig(tlsConfig)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsClientCfg,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// 1. Initial Probe
	req, _ := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("probe failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	bodyStr := string(body)

	res := &gateonv1.DiscoverTechResponse{
		Tech:         "generic_http",
		DetectedInfo: make(map[string]string),
	}

	res.DetectedInfo["status"] = fmt.Sprintf("%d", resp.StatusCode)
	res.DetectedInfo["server"] = resp.Header.Get("Server")
	res.DetectedInfo["powered_by"] = resp.Header.Get("X-Powered-By")

	// 2. Detection Logic

	// pgAdmin4 Detection
	if strings.Contains(bodyStr, "pgAdmin") || strings.Contains(targetURL, "pgadmin") || resp.Header.Get("X-pgadmin-version") != "" {
		res.Tech = "pgadmin4"
		res.Recommendations = append(res.Recommendations, &gateonv1.TechRecommendation{
			Title:           "pgAdmin4 Path Compatibility",
			Description:     "pgAdmin4 requires specific headers when hosted behind a reverse proxy sub-path.",
			SuggestedAction: "Add 'headers' middleware with X-Script-Name (matching your path) and X-Scheme: https.",
		})
		res.Recommendations = append(res.Recommendations, &gateonv1.TechRecommendation{
			Title:           "WAF Optimization",
			Description:     "pgAdmin4 performs heavy SQL-like operations which might trigger false positives.",
			SuggestedAction: "Ensure WAF 'sqli' rules are tuned or use 'audit_only' mode during initial setup.",
		})
	}

	// Synology DSM Detection
	if strings.Contains(bodyStr, "SYNO.SDS.Direct") || strings.Contains(bodyStr, "Synology") || resp.Header.Get("Set-Cookie") != "" && strings.Contains(resp.Header.Get("Set-Cookie"), "id=") {
		// Check for DSM specific paths
		dsmReq, _ := http.NewRequestWithContext(ctx, "GET", targetURL+"/webman/index.cgi", nil)
		dsmResp, err := client.Do(dsmReq)
		if err == nil {
			defer dsmResp.Body.Close()
			if dsmResp.StatusCode == 200 {
				res.Tech = "synology_dsm"
			}
		}

		if res.Tech == "synology_dsm" || strings.Contains(bodyStr, "Synology") {
			res.Tech = "synology_dsm"
			res.Recommendations = append(res.Recommendations, &gateonv1.TechRecommendation{
				Title:           "DSM WebSocket Support",
				Description:     "Synology DSM uses WebSockets for real-time UI updates.",
				SuggestedAction: "Ensure the route enables WebSocket hijacking (default in Gateon HTTP proxy).",
			})
			res.Recommendations = append(res.Recommendations, &gateonv1.TechRecommendation{
				Title:           "Security Bypass for Local Discovery",
				Description:     "DSM may use non-standard headers for UPnP/SSDP discovery.",
				SuggestedAction: "Disable WAF protocol enforcement for internal Synology management traffic.",
			})
		}
	}

	// gRPC Detection (via Content-Type or standard probe)
	if strings.Contains(resp.Header.Get("Content-Type"), "application/grpc") || resp.Header.Get("Trailer") == "grpc-status" {
		res.Tech = "grpc"
		res.Recommendations = append(res.Recommendations, &gateonv1.TechRecommendation{
			Title:           "HTTP/2 Enforcement",
			Description:     "gRPC requires HTTP/2 transport.",
			SuggestedAction: "Set service 'backend_type' to 'grpc' and ensure TLS is enabled or use h2c.",
		})
	}

	// Go / Gin / Echo Detection
	if strings.Contains(resp.Header.Get("X-Powered-By"), "Go") || strings.Contains(bodyStr, "Go Programming Language") {
		res.Tech = "golang"
		res.Recommendations = append(res.Recommendations, &gateonv1.TechRecommendation{
			Title:           "Go Runtime Observability",
			Description:     "Go services often expose /debug/pprof or /metrics.",
			SuggestedAction: "Apply an 'auth' middleware to protect sensitive internal Go diagnostics endpoints.",
		})
	}

	return res, nil
}

func extractHost(rawURL string) string {
	parts := strings.Split(rawURL, "/")
	if len(parts) < 3 {
		return rawURL
	}
	hostPort := parts[2]
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return host
}
