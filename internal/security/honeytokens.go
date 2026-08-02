// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package security

import (
	"bytes"
	"fmt"
	"math/rand"
	"net/http"
	"strings"

	"github.com/gsoultan/gateon/internal/audit"
)

// DynamicHoneytokenManager handles generation and validation of per-session traps.
type DynamicHoneytokenManager struct {
	StaticTokens map[string]string
}

func NewDynamicHoneytokenManager() *DynamicHoneytokenManager {
	return &DynamicHoneytokenManager{
		StaticTokens: DefaultHoneytokens(),
	}
}

// Middleware returns a middleware that detects access to "trap" resources and injects breadcrumbs.
func (m *DynamicHoneytokenManager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Check if the requested path is a honeytoken
		if reason, ok := m.StaticTokens[r.URL.Path]; ok {
			audit.Log(r.Context(), "system", "honeytoken_triggered", r.URL.Path, "Reason: "+reason, r.RemoteAddr)
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		// Check for dynamic breadcrumbs (e.g. /_gateon_trap_XXXX)
		if strings.HasPrefix(r.URL.Path, "/_gateon_trap_") {
			audit.Log(r.Context(), "system", "breadcrumb_triggered", r.URL.Path, "Reason: Invisible breadcrumb link followed by bot", r.RemoteAddr)
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		// 2. Prepare for breadcrumb injection if it's an HTML response
		// Note: Since we are a proxy, we might need to wrap the response writer
		// to intercept the Content-Type and body.
		bw := &breadcrumbWriter{
			ResponseWriter: w,
			request:        r,
		}

		next.ServeHTTP(bw, r)
	})
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
	// In production, this should be more robust (e.g. use a streaming parser)
	// But for our "Super Fast" requirement, we do a simple byte search.
	bodyTag := []byte("</body>")
	idx := bytes.LastIndex(b, bodyTag)
	if idx == -1 {
		return w.ResponseWriter.Write(b)
	}

	// Generate a unique trap path for this session/request
	trapID := rand.Intn(1000000)
	trapLink := fmt.Sprintf("\n<!-- Gateon Breadcrumb -->\n<a href=\"/_gateon_trap_%d\" style=\"display:none\" aria-hidden=\"true\" tabIndex=\"-1\"></a>\n", trapID)

	newBody := make([]byte, 0, len(b)+len(trapLink))
	newBody = append(newBody, b[:idx]...)
	newBody = append(newBody, []byte(trapLink)...)
	newBody = append(newBody, b[idx:]...)

	_, err := w.ResponseWriter.Write(newBody)
	return len(b), err // Return original length to satisfy http.Handler contract if needed
}

// DefaultHoneytokens provides a set of common traps.
func DefaultHoneytokens() map[string]string {
	return map[string]string{
		"/.env":             "Environment file access attempt",
		"/.git/config":      "Git configuration access attempt",
		"/wp-config.php":    "WordPress configuration access attempt",
		"/admin/config.php": "Admin configuration access attempt",
		"/backup.sql":       "Database backup access attempt",
		"/etc/passwd":       "System file access attempt",
		"/.aws/credentials": "AWS credentials access attempt",
		"/server-status":    "Apache server status access attempt",
		"/phpinfo.php":      "PHP info access attempt",
		"/actuator/env":     "Spring Boot actuator access attempt",
	}
}
