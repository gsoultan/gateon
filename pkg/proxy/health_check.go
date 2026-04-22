package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func (h *ProxyHandler) runHealthCheck() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	client := h.healthCheckClient
	if client == nil {
		transport := h.transport
		if h.transportFactory != nil {
			transport = h.transportFactory.HealthCheckTransport()
		}
		client = &http.Client{
			Timeout:   5 * time.Second,
			Transport: transport,
		}
	}

	for {
		select {
		case <-ticker.C:
			currentStats := h.lb.GetStats()
			for _, s := range currentStats {
				u := s.URL
				alive := h.checkTargetHealth(context.Background(), client, u)
				h.lb.SetAlive(u, alive)
				// Update Prometheus target health gauge
				healthVal := 0.0
				if alive {
					healthVal = 1.0
				}
				telemetry.TargetHealth.WithLabelValues(h.routeName, u).Set(healthVal)
				telemetry.ActiveConnections.WithLabelValues(u).Set(float64(s.ActiveConn))
			}
		case <-h.stopHealthCheck:
			return
		}
	}
}

func (h *ProxyHandler) checkTargetHealth(ctx context.Context, client *http.Client, targetURL string) bool {
	switch h.healthCheckType {
	case gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_GRPC:
		return h.checkGRPCHealth(ctx, targetURL)
	case gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_TCP:
		return h.checkTCPHealth(ctx, targetURL)
	case gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_CUSTOM:
		return h.checkCustomHealth(ctx, client, targetURL)
	default:
		return h.checkHTTPHealth(client, targetURL)
	}
}

func (h *ProxyHandler) checkGRPCHealth(ctx context.Context, targetURL string) bool {
	host := targetURL
	useTLS := false
	if strings.HasPrefix(targetURL, "h2c://") {
		host = strings.TrimPrefix(targetURL, "h2c://")
	} else if strings.HasPrefix(targetURL, "h2://") {
		host = strings.TrimPrefix(targetURL, "h2://")
		useTLS = true
	} else if strings.HasPrefix(targetURL, "h3://") {
		host = strings.TrimPrefix(targetURL, "h3://")
		useTLS = true
	}

	// Apply port override if configured
	if h.healthCheckPort > 0 {
		hostOnly, _, err := net.SplitHostPort(host)
		if err == nil {
			host = net.JoinHostPort(hostOnly, fmt.Sprintf("%d", h.healthCheckPort))
		} else {
			host = net.JoinHostPort(host, fmt.Sprintf("%d", h.healthCheckPort))
		}
	}

	var opts []grpc.DialOption
	if useTLS {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(h.tlsConfig)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(dialCtx, host, opts...)
	if err != nil {
		return false
	}
	defer func() {
		_ = conn.Close()
	}()

	client := grpc_health_v1.NewHealthClient(conn)
	resp, err := client.Check(dialCtx, &grpc_health_v1.HealthCheckRequest{
		Service: h.healthCheckPath,
	})

	return err == nil && resp != nil && resp.Status == grpc_health_v1.HealthCheckResponse_SERVING
}

func (h *ProxyHandler) checkHTTPHealth(client *http.Client, targetURL string) bool {
	healthURL := h.buildHealthCheckURL(targetURL)
	resp, err := client.Get(healthURL)
	alive := err == nil && resp != nil && resp.StatusCode < 500
	if resp != nil {
		_ = resp.Body.Close()
	}
	return alive
}

func (h *ProxyHandler) checkTCPHealth(ctx context.Context, targetURL string) bool {
	host := h.targetHostForHealth(targetURL)
	if host == "" {
		return false
	}

	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(checkCtx, "tcp", host)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (h *ProxyHandler) checkCustomHealth(ctx context.Context, client *http.Client, targetURL string) bool {
	proto := strings.ToLower(strings.TrimSpace(h.healthCheckProtocol))
	switch proto {
	case "grpc", "h2", "h2c":
		return h.checkGRPCHealth(ctx, targetURL)
	case "tcp":
		return h.checkTCPHealth(ctx, targetURL)
	default:
		if h.healthCheckPath == "" {
			return h.checkTCPHealth(ctx, targetURL)
		}
		return h.checkHTTPHealth(client, targetURL)
	}
}

func (h *ProxyHandler) targetHostForHealth(targetURL string) string {
	host := targetURL
	if strings.HasPrefix(targetURL, "h2c://") {
		host = strings.TrimPrefix(targetURL, "h2c://")
	} else if strings.HasPrefix(targetURL, "h2://") {
		host = strings.TrimPrefix(targetURL, "h2://")
	} else if strings.HasPrefix(targetURL, "h3://") {
		host = strings.TrimPrefix(targetURL, "h3://")
	} else if strings.HasPrefix(targetURL, "http://") {
		host = strings.TrimPrefix(targetURL, "http://")
	} else if strings.HasPrefix(targetURL, "https://") {
		host = strings.TrimPrefix(targetURL, "https://")
	}

	if h.healthCheckPort > 0 {
		hostOnly, _, err := net.SplitHostPort(host)
		if err == nil {
			return net.JoinHostPort(hostOnly, fmt.Sprintf("%d", h.healthCheckPort))
		}
		return net.JoinHostPort(host, fmt.Sprintf("%d", h.healthCheckPort))
	}

	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}

	switch {
	case strings.HasPrefix(targetURL, "https://"), strings.HasPrefix(targetURL, "h2://"), strings.HasPrefix(targetURL, "h3://"):
		return net.JoinHostPort(host, "443")
	default:
		return net.JoinHostPort(host, "80")
	}
}

func (h *ProxyHandler) buildHealthCheckURL(targetURL string) string {
	uForHealth := targetURL
	if strings.HasPrefix(targetURL, "h2c://") {
		uForHealth = "http://" + strings.TrimPrefix(targetURL, "h2c://")
	} else if strings.HasPrefix(targetURL, "h2://") || strings.HasPrefix(targetURL, "h3://") {
		uForHealth = "https://" + strings.TrimPrefix(strings.TrimPrefix(targetURL, "h2://"), "h3://")
	}

	parsed, err := url.Parse(uForHealth)
	if err != nil {
		return strings.TrimSuffix(uForHealth, "/") + h.healthCheckPath
	}

	if h.healthCheckProtocol != "" {
		parsed.Scheme = h.healthCheckProtocol
	}

	if h.healthCheckPort > 0 {
		host := parsed.Hostname()
		parsed.Host = net.JoinHostPort(host, fmt.Sprintf("%d", h.healthCheckPort))
	}

	parsed.Path = h.healthCheckPath
	return parsed.String()
}
