package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

var upgrader = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

// aggRateEstimator derives a system-wide requests/second figure from the
// monotonically-increasing cumulative request total across successive agg-stats
// calls. It is process-wide and guarded by a mutex; the sample is only refreshed
// once at least a second has elapsed so that bursty multi-client polling does not
// produce noisy or divide-by-near-zero rates. The last computed rate is returned
// between refreshes. This keeps the agg-stats contract consistent (the field is
// always present and tracks total_requests' growth) without inventing a number.
var aggRate = &rateEstimator{}

type rateEstimator struct {
	mu        sync.Mutex
	lastTotal uint64
	lastAt    time.Time
	rate      float64
}

func (e *rateEstimator) observe(total uint64, now time.Time) float64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lastAt.IsZero() {
		e.lastTotal, e.lastAt = total, now
		return 0
	}
	elapsed := now.Sub(e.lastAt).Seconds()
	if elapsed < 1 {
		return e.rate
	}
	// Counters can reset (process restart) — clamp negative deltas to zero.
	var delta float64
	if total >= e.lastTotal {
		delta = float64(total - e.lastTotal)
	}
	e.rate = delta / elapsed
	e.lastTotal, e.lastAt = total, now
	return e.rate
}

// isBlockedIP reports whether an address is in a range that must never be
// reachable via the diagnostics test-target (SSRF protection).
func isBlockedIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// hostResolvesToBlockedIP resolves host and returns true if it is (or resolves
// to) a blocked address. A bare IP literal is checked directly.
func hostResolvesToBlockedIP(ctx context.Context, host string) (bool, string) {
	if host == "" {
		return true, "invalid target host"
	}
	if strings.EqualFold(host, "localhost") {
		return true, "access to localhost is forbidden"
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if isBlockedIP(addr) {
			return true, "access to internal addresses is forbidden"
		}
		return false, ""
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return true, "failed to resolve target host"
	}
	for _, ip := range ips {
		if addr, ok := netip.AddrFromSlice(ip); ok && isBlockedIP(addr) {
			return true, "access to internal addresses is forbidden"
		}
	}
	return false, ""
}

// ssrfSafeTransport returns an http.Transport whose dialer re-validates the
// resolved IP at connect time, defeating DNS-rebinding attacks where the host
// passed initial validation but later resolves to an internal address.
func ssrfSafeTransport() *http.Transport {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if blocked, msg := hostResolvesToBlockedIP(ctx, host); blocked {
				return nil, fmt.Errorf("ssrf blocked: %s", msg)
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
}

func isLogsRequestAuthorized(r *http.Request, verifier middleware.TokenVerifier) bool {
	claimsVal := r.Context().Value(middleware.UserContextKey)
	if claimsVal != nil {
		claims, ok := claimsVal.(*auth.Claims)
		if !ok || claims == nil {
			return false
		}
		// Only Admin and Operator can see logs
		return auth.Allowed(r.Context(), claims.Role, auth.ActionRead, auth.ResourceGlobal)
	}

	if verifier == nil {
		// Auth disabled
		return true
	}

	// Try extracting from query params (needed for WebSockets if middleware didn't run)
	// or if we want to support manual verification.
	token := middleware.ExtractToken(r)
	if token == "" {
		return false
	}
	claimsRaw, err := verifier.VerifyToken(token)
	if err != nil {
		return false
	}
	claims, ok := claimsRaw.(*auth.Claims)
	if !ok || claims == nil {
		return false
	}
	return auth.Allowed(r.Context(), claims.Role, auth.ActionRead, auth.ResourceGlobal)
}

func registerDiagnosticHandlers(mux *http.ServeMux, svc GlobalAndAuthAPI, d *Deps) {
	mux.HandleFunc("GET /v1/diagnostics", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceGlobal) {
			return
		}
		res, err := svc.GetDiagnostics(r.Context(), &gateonv1.GetDiagnosticsRequest{})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		data, _ := ProtojsonOptions().Marshal(res)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /v1/diagnostics/watch", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceGlobal) {
			return
		}
		SetSSEHeaders(w)

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				res, err := svc.GetDiagnostics(r.Context(), &gateonv1.GetDiagnosticsRequest{})
				if err != nil {
					return
				}
				data, _ := ProtojsonOptions().Marshal(res)
				_, _ = fmt.Fprintf(w, "data: %s\n\n", string(data))
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	})
	mux.HandleFunc("POST /v1/diagnostics/recommendation", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceGlobal) {
			return
		}
		var req gateonv1.ApplyRecommendationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		res, err := svc.ApplyRecommendation(r.Context(), &req)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		data, _ := ProtojsonOptions().Marshal(res)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("POST /v1/diagnostics/remove-mitigation", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceGlobal) {
			return
		}
		var req gateonv1.RemoveMitigatedThreatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		res, err := svc.RemoveMitigatedThreat(r.Context(), &req)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		data, _ := ProtojsonOptions().Marshal(res)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("POST /v1/diagnostics/traceroute", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceGlobal) {
			return
		}
		var req gateonv1.TraceRouteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		res, err := svc.TraceRoute(r.Context(), &req)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		data, _ := ProtojsonOptions().Marshal(res)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /v1/logs", func(w http.ResponseWriter, r *http.Request) {
		if !isLogsRequestAuthorized(r, d.AuthManager) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		logCh, history := logger.Broadcaster.Subscribe()
		defer logger.Broadcaster.Unsubscribe(logCh)

		// Send history first
		for _, msg := range history {
			if err := conn.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
				return
			}
		}

		for {
			select {
			case msg, ok := <-logCh:
				if !ok {
					return
				}
				if err := conn.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
					return
				}
			case <-r.Context().Done():
				return
			}
		}
	})
	mux.HandleFunc("GET /v1/diag/sys", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceGlobal) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"os": runtime.GOOS, "arch": runtime.GOARCH, "cpus": runtime.NumCPU(),
			"goroutines": runtime.NumGoroutine(), "version": runtime.Version(),
			"uptime_seconds": time.Since(d.StartTime).Seconds(), "memory_alloc": m.Alloc,
		})
	})
	mux.HandleFunc("GET /v1/diag/limit-stats", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceGlobal) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(telemetry.GetLimitStats())
	})
	mux.HandleFunc("GET /v1/diag/circuit-breaker/events", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceGlobal) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(telemetry.GetCircuitBreakerEvents())
	})
	mux.HandleFunc("GET /v1/diag/agg-stats", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceGlobal) {
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		if d.RouteStatsProvider == nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"total_requests": 0, "requests_per_second": 0, "total_errors": 0,
				"active_connections": 0, "open_circuits": 0, "half_open_circuits": 0,
				"healthy_targets": 0, "total_targets": 0, "total_bandwidth_bytes": 0,
			})
			return
		}
		// RouteService is on api config, not Deps. Use RouteStatsProvider for each route.
		// We need route IDs - get from route handler deps. Deps has RouteService via registerRouteHandlers.
		// registerDiagnosticHandlers receives same d - Deps has RouteService.
		routes, _ := d.RouteService.ListPaginated(ctx, 0, 500, "", nil)
		var totalReqs, totalErrs, activeConn uint64
		var openCircuits, halfOpenCircuits, healthyTargets, totalTargets int
		for _, rt := range routes {
			stats := d.RouteStatsProvider(rt.Id)
			for _, s := range stats {
				totalReqs += s.RequestCount
				totalErrs += s.ErrorCount
				activeConn += uint64(s.ActiveConn)
				totalTargets++
				circuit := s.CircuitState
				if circuit == "" {
					if s.Alive {
						circuit = "CLOSED"
					} else {
						circuit = "OPEN"
					}
				}
				switch circuit {
				case "OPEN":
					openCircuits++
				case "HALF-OPEN":
					halfOpenCircuits++
				case "CLOSED":
					healthyTargets++
				}
			}
		}
		pathStats := telemetry.GetPathStats(ctx)
		var pathTotalReqs uint64
		var pathTotalBandwidth uint64
		for _, p := range pathStats {
			pathTotalReqs += p.RequestCount
			pathTotalBandwidth += p.BytesTotal
		}

		// Calculate total requests: prefer route stats if available, otherwise use path stats
		finalTotalReqs := totalReqs
		if finalTotalReqs < pathTotalReqs {
			finalTotalReqs = pathTotalReqs
		}

		// Get system metrics from latest snapshot
		var cpuUsage, memUsage float64
		if snap, err := telemetry.CollectMetricsSnapshot(ctx, 50, 0); err == nil {
			cpuUsage = snap.System.CPUUsage
			memUsage = snap.System.MemoryUsage
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total_requests":        finalTotalReqs,
			"requests_per_second":   aggRate.observe(finalTotalReqs, time.Now()),
			"total_bandwidth_bytes": pathTotalBandwidth,
			"total_errors":          totalErrs,
			"active_connections":    activeConn,
			"open_circuits":         openCircuits,
			"half_open_circuits":    halfOpenCircuits,
			"healthy_targets":       healthyTargets,
			"total_targets":         totalTargets,
			"cpu_usage":             cpuUsage,
			"memory_usage":          memUsage,
		})
	})
	mux.HandleFunc("GET /v1/diag/path-stats", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceGlobal) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		daysStr := r.URL.Query().Get("days")
		if daysStr != "" {
			if days, err := strconv.Atoi(daysStr); err == nil {
				stats := telemetry.GetPathStatsWindow(r.Context(), days)
				_ = json.NewEncoder(w).Encode(stats)
				return
			}
		}
		stats := telemetry.GetPathStats(r.Context())
		_ = json.NewEncoder(w).Encode(stats)
	})
	mux.HandleFunc("GET /v1/diag/metrics", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceGlobal) {
			return
		}
		limit := 50
		if lStr := r.URL.Query().Get("limit"); lStr != "" {
			if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
				limit = l
			}
		}
		offset := 0
		if oStr := r.URL.Query().Get("offset"); oStr != "" {
			if o, err := strconv.Atoi(oStr); err == nil && o >= 0 {
				offset = o
			}
		} else if pStr := r.URL.Query().Get("page"); pStr != "" {
			if p, err := strconv.Atoi(pStr); err == nil && p > 0 {
				offset = (p - 1) * limit
			}
		}

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		snap, err := telemetry.CollectMetricsSnapshot(ctx, limit, offset)
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		WriteJSON(w, http.StatusOK, snap)
	})
	mux.HandleFunc("GET /v1/diag/metrics/watch", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceGlobal) {
			return
		}
		SetSSEHeaders(w)

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
				snap, err := telemetry.CollectMetricsSnapshot(ctx, 50, 0)
				cancel()
				if err != nil {
					return
				}
				data, _ := json.Marshal(snap)
				_, _ = fmt.Fprintf(w, "data: %s\n\n", string(data))
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	})
	mux.HandleFunc("POST /v1/diag/test-target", func(w http.ResponseWriter, r *http.Request) {
		// Restrict to Admin only as this can be used for SSRF
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceGlobal) {
			return
		}
		var req struct {
			Target string `json:"target"`
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if req.Target == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// SSRF prevention: validate URL
		u, err := url.Parse(req.Target)
		if err != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") {
			WriteHTTPError(w, http.StatusBadRequest, "invalid target url")
			return
		}
		// Resolve the host now and reject any address in a loopback / private /
		// link-local (incl. cloud metadata 169.254.169.254) / ULA / unspecified
		// range. This is re-checked at dial time below to defeat DNS rebinding.
		if blocked, msg := hostResolvesToBlockedIP(r.Context(), u.Hostname()); blocked {
			WriteHTTPError(w, http.StatusBadRequest, msg)
			return
		}

		if req.Method == "" {
			req.Method = "GET"
		}
		client := &http.Client{Timeout: 5 * time.Second, Transport: ssrfSafeTransport()}
		proxyReq, err := http.NewRequestWithContext(r.Context(), req.Method, req.Target, nil)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		resp, err := client.Do(proxyReq)
		if err != nil {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": resp.StatusCode < 400, "status_code": resp.StatusCode, "headers": resp.Header,
		})
	})
	mux.HandleFunc("GET /v1/diag/security-threats", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceGlobal) {
			return
		}
		limit := 50
		if lStr := r.URL.Query().Get("limit"); lStr != "" {
			if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
				limit = l
			}
		}
		res, err := svc.ListSecurityThreats(r.Context(), &gateonv1.ListSecurityThreatsRequest{Limit: int32(limit)})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		data, _ := ProtojsonOptions().Marshal(res)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /v1/diag/security-threats/watch", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceGlobal) {
			return
		}
		SetSSEHeaders(w)

		ch := telemetry.ThreatBroadcaster.Subscribe()
		defer telemetry.ThreatBroadcaster.Unsubscribe(ch)

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		for {
			select {
			case threat, ok := <-ch:
				if !ok {
					return
				}
				data, _ := json.Marshal(threat)
				_, _ = fmt.Fprintf(w, "data: %s\n\n", string(data))
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	})
	mux.HandleFunc("GET /v1/security/reputations", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceGlobal) {
			return
		}
		limit := 20
		if lStr := r.URL.Query().Get("limit"); lStr != "" {
			if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
				limit = l
			}
		}
		res, err := svc.ListReputations(r.Context(), &gateonv1.ListReputationsRequest{Limit: int32(limit)})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		data, _ := ProtojsonOptions().Marshal(res)
		_, _ = w.Write(data)
	})
}
