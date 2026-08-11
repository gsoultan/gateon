// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"net/http"
	"strings"
	"time"

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
	trapID := newTrapID()
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
	// #nosec G101 -- decoy paths for the honeypot. They exist to be requested
	// by scanners; none is a real secret or a real file.
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

// newTrapID returns an unpredictable identifier for a honeytoken trap path.
//
// crypto/rand rather than math/rand, and that is the mechanism rather than a
// lint fix. A honeytoken only works if an attacker cannot tell a trap from a
// real path; with a predictable generator the sequence is reproducible offline,
// every trap can be enumerated and avoided, and the deception layer becomes an
// oracle for exactly the visitors it exists to catch. The space widens at the
// same time -- a million values is small enough to sweep.
//
// Deliberately duplicated from internal/middleware rather than shared: it is
// eight lines, and a util package coupling security to middleware would cost
// more than the duplication.
func newTrapID() uint64 {
	var b [8]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		// crypto/rand does not fail in practice, and a trap that silently
		// became predictable would be worse than no trap. Fall back to the
		// clock, which is still not enumerable offline.
		return uint64(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint64(b[:])
}
