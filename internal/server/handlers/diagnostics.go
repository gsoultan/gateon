package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

var upgrader = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

func isLogsRequestAuthorized(r *http.Request, verifier middleware.TokenVerifier) bool {
	claimsVal := r.Context().Value(middleware.UserContextKey)
	if claimsVal != nil {
		claims, ok := claimsVal.(*auth.Claims)
		if !ok || claims == nil {
			return false
		}
		// Only Admin and Operator can see logs
		return auth.Allowed(claims.Role, auth.ActionRead, auth.ResourceGlobal)
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
	return auth.Allowed(claims.Role, auth.ActionRead, auth.ResourceGlobal)
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
		routes, _ := d.RouteService.ListPaginated(context.Background(), 0, 500, "", nil)
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
		pathStats := telemetry.GetPathStats(r.Context())
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
		if snap, err := telemetry.CollectMetricsSnapshot(); err == nil {
			cpuUsage = snap.System.CPUUsage
			memUsage = snap.System.MemoryUsage
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total_requests":        finalTotalReqs,
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
		snap, err := telemetry.CollectMetricsSnapshot()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(snap)
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
			writeJSONError(w, http.StatusBadRequest, "invalid target url")
			return
		}
		// Basic SSRF: reject loopback
		if u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1" {
			writeJSONError(w, http.StatusBadRequest, "access to localhost is forbidden")
			return
		}

		if req.Method == "" {
			req.Method = "GET"
		}
		client := &http.Client{Timeout: 5 * time.Second}
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
}
