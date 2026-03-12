package handlers

import (
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
		proxyReq, err := http.NewRequest(req.Method, req.Target, nil)
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
