// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package middleware

import (
	"bytes"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
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
			clientIP := request.GetClientIP(r, config.EffectiveTrustCloudflare())

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
			deceptionEnabled := false
			if gc != nil && gc.SecurityAdvanced != nil && gc.SecurityAdvanced.Deception != nil && gc.SecurityAdvanced.Deception.Enabled {
				paths = gc.SecurityAdvanced.Deception.HoneypotPaths
				deceptionEnabled = true
			}

			if len(paths) == 0 {
				// Use defaults if none configured but middleware is active
				paths = []string{"/.env", "/wp-admin", "/admin", "/.git", "/config.php", "/backup.sql", "/.aws", "/.ssh"}
			}

			path := r.URL.Path

			// Check for breadcrumb triggers first
			if strings.HasPrefix(path, "/_gateon_trap_") {
				recordHoneypotThreat(r, "dynamic_breadcrumb")
				blocklistMu.Lock()
				honeypotBlocklist[clientIP] = time.Now().Add(24 * time.Hour)
				blocklistMu.Unlock()
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			for _, trapPath := range paths {
				if trapPath == "" {
					continue
				}
				// Exact match or prefix match for directories
				if path == trapPath || strings.HasPrefix(path, trapPath+"/") {
					recordHoneypotThreat(r, trapPath)

					blocklistMu.Lock()
					honeypotBlocklist[clientIP] = time.Now().Add(24 * time.Hour)
					blocklistMu.Unlock()

					// Return 403 Forbidden to the attacker
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
			}

			// If deception is enabled, wrap ResponseWriter to inject breadcrumbs
			if deceptionEnabled {
				bw := &breadcrumbWriter{
					ResponseWriter: w,
					request:        r,
				}
				next.ServeHTTP(bw, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

type breadcrumbWriter struct {
	http.ResponseWriter
	request     *http.Request
	wroteHeader bool
	isHTML      bool
}

func (w *breadcrumbWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	contentType := w.Header().Get("Content-Type")
	if strings.Contains(contentType, "text/html") && code == http.StatusOK {
		w.isHTML = true
		// Remove Content-Length as we will modify the body
		w.Header().Del("Content-Length")
	}
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *breadcrumbWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if !w.isHTML {
		return w.ResponseWriter.Write(b)
	}

	// Simple breadcrumb injection: find </body> and insert a hidden link
	bodyTag := []byte("</body>")
	idx := bytes.LastIndex(b, bodyTag)
	if idx == -1 {
		return w.ResponseWriter.Write(b)
	}

	// Generate a unique trap path
	trapID := rand.Intn(1000000)
	trapLink := fmt.Sprintf("\n<!-- Gateon Breadcrumb -->\n<a href=\"/_gateon_trap_%d\" style=\"display:none\" aria-hidden=\"true\" tabIndex=\"-1\"></a>\n", trapID)

	newBody := make([]byte, 0, len(b)+len(trapLink))
	newBody = append(newBody, b[:idx]...)
	newBody = append(newBody, []byte(trapLink)...)
	newBody = append(newBody, b[idx:]...)

	_, err := w.ResponseWriter.Write(newBody)
	// We return len(b) to pretend we wrote exactly what was given,
	// although we wrote more. Some middlewares might care.
	return len(b), err
}

// Honeypot returns a middleware that detects access to "trap" paths and blocks them.
func Honeypot(cfg HoneypotConfig) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := request.GetClientIP(r, config.EffectiveTrustCloudflare())

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
					recordHoneypotThreat(r, trapPath)

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

func recordHoneypotThreat(r *http.Request, trapPath string) {
	clientIP := request.GetClientIP(r, config.EffectiveTrustCloudflare())
	routeID := GetRouteName(r)
	if routeID == "" {
		routeID = "global-honeypot"
	}

	logger.SecurityEvent("honeypot_triggered", r, "access to trap path: "+trapPath+"; IP blocked for 24h")

	telemetry.RecordSecurityThreat(telemetry.RecordSecurityThreatWithJA4(r, telemetry.SecurityThreat{
		Type:        "honeypot_triggered",
		SourceIP:    clientIP,
		Score:       100,
		Details:     "Access to deception trap path: " + trapPath,
		Time:        time.Now(),
		RouteID:     routeID,
		RequestURI:  r.URL.Path,
		Category:    "deception",
		Severity:    "high",
		ActionTaken: "blocked",
	}))
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
