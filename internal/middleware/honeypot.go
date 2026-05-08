package middleware

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
)

var (
	honeypotBlocklist = make(map[string]time.Time)
	blocklistMu       sync.RWMutex
)

// HoneypotConfig defines the configuration for the Honeypot middleware.
type HoneypotConfig struct {
	Paths []string
}

// HoneypotGlobal returns a middleware that detects access to "trap" paths and blocks them globally.
func HoneypotGlobal(globalStore config.GlobalConfigStore) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := request.GetClientIP(r, request.TrustCloudflareFromEnv())

			blocklistMu.RLock()
			until, blocked := honeypotBlocklist[clientIP]
			blocklistMu.RUnlock()

			if blocked {
				if time.Now().Before(until) {
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
				// Expired
				blocklistMu.Lock()
				delete(honeypotBlocklist, clientIP)
				blocklistMu.Unlock()
			}

			gc := globalStore.Get(r.Context())
			var paths []string
			if gc != nil && gc.SecurityAdvanced != nil && gc.SecurityAdvanced.Deception != nil && gc.SecurityAdvanced.Deception.Enabled {
				paths = gc.SecurityAdvanced.Deception.HoneypotPaths
			}

			if len(paths) == 0 {
				// Use defaults if none configured but middleware is active
				paths = []string{"/.env", "/wp-admin", "/admin", "/.git", "/config.php", "/backup.sql", "/.aws", "/.ssh"}
			}

			path := r.URL.Path
			for _, trapPath := range paths {
				if trapPath == "" {
					continue
				}
				// Exact match or prefix match for directories
				if path == trapPath || strings.HasPrefix(path, trapPath+"/") {
					logger.SecurityEvent("honeypot_triggered", r, "access to trap path: "+trapPath+"; IP blocked for 24h")

					blocklistMu.Lock()
					honeypotBlocklist[clientIP] = time.Now().Add(24 * time.Hour)
					blocklistMu.Unlock()

					// Return 403 Forbidden to the attacker
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Honeypot returns a middleware that detects access to "trap" paths and blocks them.
func Honeypot(cfg HoneypotConfig) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := request.GetClientIP(r, request.TrustCloudflareFromEnv())

			blocklistMu.RLock()
			until, blocked := honeypotBlocklist[clientIP]
			blocklistMu.RUnlock()

			if blocked {
				if time.Now().Before(until) {
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
				// Expired
				blocklistMu.Lock()
				delete(honeypotBlocklist, clientIP)
				blocklistMu.Unlock()
			}

			path := r.URL.Path
			for _, trapPath := range cfg.Paths {
				if trapPath == "" {
					continue
				}
				// Exact match or prefix match for directories
				if path == trapPath || strings.HasPrefix(path, trapPath+"/") {
					logger.SecurityEvent("honeypot_triggered", r, "access to trap path: "+trapPath+"; IP blocked for 24h")

					blocklistMu.Lock()
					honeypotBlocklist[clientIP] = time.Now().Add(24 * time.Hour)
					blocklistMu.Unlock()

					// Return 403 Forbidden to the attacker
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// parseHoneypotConfig parses the middleware configuration into HoneypotConfig.
func parseHoneypotConfig(cfg map[string]string) HoneypotConfig {
	pathsStr := cfg["paths"]
	if pathsStr == "" {
		// Default common trap paths if none provided
		return HoneypotConfig{
			Paths: []string{
				"/.env",
				"/wp-admin",
				"/admin",
				"/.git",
				"/config.php",
				"/backup.sql",
				"/.aws",
				"/.ssh",
			},
		}
	}

	parts := strings.Split(pathsStr, ",")
	paths := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			if !strings.HasPrefix(p, "/") {
				p = "/" + p
			}
			paths = append(paths, p)
		}
	}
	return HoneypotConfig{Paths: paths}
}
