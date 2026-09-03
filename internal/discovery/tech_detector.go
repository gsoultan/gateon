// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

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
	"syscall"
	"time"

	gtls "github.com/gsoultan/gateon/internal/tls"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TechDetector probes a backend service to identify its technology stack and provide configuration recommendations.
type TechDetector struct {
	// blockedTarget decides which resolved addresses the probe refuses to
	// connect to. nil means blockedProbeTarget, the production policy; tests
	// replace it so they can probe an httptest server, which always binds
	// loopback. It exists because the previous escape hatch was
	// `os.Getenv("GATEON_TEST") != "1"` guarding the whole check -- an
	// environment variable that switched off an SSRF control for the process.
	blockedTarget func(net.IP) (reason string, blocked bool)
}

// blockedProbeTarget reports whether the probe must refuse an address.
//
// The check happens in the dialer rather than on the URL, because the URL is
// attacker-supplied and every string-level check on it has a bypass. The
// previous one had several: it parsed the host by splitting on "/", so
// http://evil.com@127.0.0.1/ yielded the host "evil.com@127.0.0.1", which fails
// to resolve, and a failed resolve skipped the check entirely. http://[::1]/
// kept its brackets and failed the same way. It compared for equality with
// "127.0.0.1", so 127.0.0.2 -- or any of the other sixteen million loopback
// addresses -- passed. It never looked at 169.254.169.254 at all. And even a
// correct URL check is defeated by DNS rebinding, since the name is resolved
// once for the check and again for the connection.
//
// Dialing is the only place that sees the address actually being connected to,
// after resolution, on the original request and on every redirect.
//
// RFC1918 private addresses are deliberately allowed: probing a backend on
// 10.0.0.5 or a NAS on 192.168.1.10 is what this feature is for. What is
// refused is the machine itself and the addresses that are dangerous precisely
// because the gateway can reach them and the caller cannot.
func blockedProbeTarget(ip net.IP) (string, bool) {
	switch {
	case ip == nil:
		return "unparseable", true
	case ip.IsLoopback():
		// Blocks all of 127.0.0.0/8 and ::1, including the gateway's own
		// management API if it is bound to loopback.
		//
		// A gateway running beside its backend in one pod or container is a
		// real deployment, and there the backend genuinely is on 127.0.0.1, so
		// this one case can be opted into. It is deliberately its own switch
		// rather than a general "skip the SSRF check": it permits loopback and
		// nothing else, and the link-local case below stays refused however it
		// is set, because that is the one that leaks credentials.
		if allowLoopbackProbes() {
			return "", false
		}
		return "loopback; set GATEON_ALLOW_LOOPBACK_PROBE=1 if the backend really is on this host", true
	case ip.IsLinkLocalUnicast():
		// 169.254.0.0/16 and fe80::/10. This is the cloud metadata service:
		// on EC2, 169.254.169.254 hands out the instance's IAM credentials to
		// anything that can reach it, which would turn "may edit services"
		// into control of the account.
		return "link-local, which is where cloud instance metadata lives", true
	case ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast():
		return "link-local multicast", true
	case ip.IsUnspecified():
		// 0.0.0.0 and :: route to the local host on most stacks.
		return "unspecified", true
	}
	return "", false
}

// allowLoopbackProbes reports whether probing 127.0.0.0/8 and ::1 is permitted.
//
// Read per probe rather than cached: DiscoverTech is an operator-initiated RPC,
// not request-path work, so the lookup costs nothing that matters and picking up
// a change without a restart is worth more than the nanoseconds.
func allowLoopbackProbes() bool {
	switch strings.TrimSpace(strings.ToLower(os.Getenv("GATEON_ALLOW_LOOPBACK_PROBE"))) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// refuseBlockedAddress is the net.Dialer Control hook. It runs after the name
// has been resolved and before the socket connects, with the address the
// connection is actually about to use.
func (d *TechDetector) refuseBlockedAddress(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("refusing to probe %q: cannot read its address: %w", address, err)
	}
	blocked := d.blockedTarget
	if blocked == nil {
		blocked = blockedProbeTarget
	}
	if reason, deny := blocked(net.ParseIP(host)); deny {
		return fmt.Errorf("refusing to probe %s: %s address", host, reason)
	}
	return nil
}

// Discover probes the given URL and returns identified technology and recommendations.
func (d *TechDetector) Discover(ctx context.Context, targetURL string, tlsConfig *gateonv1.TlsClientConfig) (*gateonv1.DiscoverTechResponse, error) {
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + targetURL
	}

	var tlsClientCfg *tls.Config
	if strings.HasPrefix(targetURL, "https://") {
		tlsClientCfg, _ = gtls.CreateTLSClientConfig(tlsConfig)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsClientCfg,
			// SSRF prevention. See blockedProbeTarget: this is checked per
			// connection, so it also covers the redirects allowed below.
			DialContext: (&net.Dialer{
				Timeout: 10 * time.Second,
				Control: d.refuseBlockedAddress,
			}).DialContext,
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
