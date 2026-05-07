package middleware

import (
	"net/http"
	"strings"

	"github.com/gsoultan/gateon/internal/logger"
)

// HoneypotConfig defines the configuration for the Honeypot middleware.
type HoneypotConfig struct {
	Paths []string
}

// Honeypot returns a middleware that detects access to "trap" paths and blocks them.
// This is an advanced detection technique to identify malicious scanners and bots.
func Honeypot(cfg HoneypotConfig) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			for _, trapPath := range cfg.Paths {
				if trapPath == "" {
					continue
				}
				// Exact match or prefix match for directories
				if path == trapPath || strings.HasPrefix(path, trapPath+"/") {
					logger.SecurityEvent("honeypot_triggered", r, "access to trap path: "+trapPath)

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
