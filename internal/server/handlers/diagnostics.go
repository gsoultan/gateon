package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gateon/gateon/internal/logger"
	"github.com/gateon/gateon/internal/telemetry"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

func registerDiagnosticHandlers(mux *http.ServeMux, d *Deps) {
	mux.HandleFunc("GET /v1/logs", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("auth")
		if token == "" {
			if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
				token = strings.TrimPrefix(h, "Bearer ")
			}
		}
		if token == "" || d.AuthManager == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if _, err := d.AuthManager.VerifyToken(token); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		logCh := logger.Broadcaster.Subscribe()
		defer logger.Broadcaster.Unsubscribe(logCh)
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
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(telemetry.GetLimitStats())
	})
	mux.HandleFunc("GET /v1/diag/agg-stats", func(w http.ResponseWriter, r *http.Request) {
		if d.RouteStatsProvider == nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"total_requests": 0, "requests_per_second": 0, "total_errors": 0,
				"active_connections": 0, "open_circuits": 0, "half_open_circuits": 0,
				"healthy_targets": 0, "total_targets": 0,
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
		pathStats := telemetry.GetPathStats()
		var pathTotalReqs uint64
		for _, p := range pathStats {
			pathTotalReqs += p.RequestCount
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total_requests":     pathTotalReqs,
			"total_errors":       totalErrs,
			"active_connections": activeConn,
			"open_circuits":      openCircuits,
			"half_open_circuits": halfOpenCircuits,
			"healthy_targets":    healthyTargets,
			"total_targets":      totalTargets,
		})
	})
	mux.HandleFunc("GET /v1/diag/path-stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		daysStr := r.URL.Query().Get("days")
		if daysStr != "" {
			if days, err := strconv.Atoi(daysStr); err == nil {
				stats := telemetry.GetPathStatsWindow(days)
				_ = json.NewEncoder(w).Encode(stats)
				return
			}
		}
		stats := telemetry.GetPathStats()
		_ = json.NewEncoder(w).Encode(stats)
	})
	mux.HandleFunc("POST /v1/diag/test-target", func(w http.ResponseWriter, r *http.Request) {
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
