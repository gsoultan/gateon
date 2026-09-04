// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"bufio"
	"bytes"
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

var (
	honeypotBlocklist = make(map[string]time.Time)
	honeypotStrikes   = make(map[string]honeypotStrike)
	blocklistMu       sync.RWMutex
)

// honeypotStrike counts how many times one address has reached a trap, and when
// it last did, so a ban can escalate rather than starting at its maximum.
type honeypotStrike struct {
	count int
	last  time.Time
}

// honeypotBanLadder is how long an address is banned for on its 1st, 2nd, 3rd
// and subsequent trap hits.
//
// A single hit used to cost 24 hours. The trap paths are chosen so that no
// legitimate client requests them (/.env, /.git, /.aws ...), which makes one hit
// strong evidence about the *request* — but the ban lands on an address, and an
// address is shared. Behind CGNAT or a corporate egress, one security scan the
// customer ran themselves, one compromised laptop, or one over-eager crawler
// took the whole office off the site until the next day.
//
// Escalation is the corroboration. A one-off costs fifteen minutes, which is
// unremarkable if it was a mistake and useless to an attacker; anyone who comes
// back reaches the full day quickly, and repetition over time is exactly the
// independent evidence a single request cannot supply. This is the same
// principle internal/security/mitigation applies to correlated incidents:
// escalate on repetition rather than act at maximum severity on first contact.
var honeypotBanLadder = []time.Duration{
	15 * time.Minute,
	1 * time.Hour,
	6 * time.Hour,
	24 * time.Hour,
}

// honeypotStrikeWindow is how long a strike counts toward escalation. An address
// that stays away for a day starts again at the bottom of the ladder, so a
// dynamic address reassigned to someone else does not inherit a stranger's
// record.
const honeypotStrikeWindow = 24 * time.Hour

// honeypotBanFor records a strike for clientIP and returns how long it should be
// banned. Callers hold no lock; this takes it.
func honeypotBanFor(clientIP string, now time.Time) time.Duration {
	blocklistMu.Lock()
	defer blocklistMu.Unlock()

	st := honeypotStrikes[clientIP]
	if now.Sub(st.last) > honeypotStrikeWindow {
		st.count = 0
	}
	st.count++
	st.last = now

	// Bounded by the same cap as the blocklist and swept the same way: this map
	// is keyed by attacker-supplied addresses, so it needs a ceiling for the
	// same reason.
	if _, exists := honeypotStrikes[clientIP]; !exists && len(honeypotStrikes) >= maxHoneypotBlocklist {
		for ip, s := range honeypotStrikes {
			if now.Sub(s.last) > honeypotStrikeWindow {
				delete(honeypotStrikes, ip)
			}
		}
		if len(honeypotStrikes) >= maxHoneypotBlocklist {
			// Cannot record the strike, so escalation is unavailable. Fall back to
			// the top of the ladder rather than the bottom: under a scan large
			// enough to fill this map, being generous to each new address is how
			// the trap stops working at exactly the moment it is needed.
			return honeypotBanLadder[len(honeypotBanLadder)-1]
		}
	}
	honeypotStrikes[clientIP] = st

	if st.count > len(honeypotBanLadder) {
		return honeypotBanLadder[len(honeypotBanLadder)-1]
	}
	return honeypotBanLadder[st.count-1]
}

// maxHoneypotBlocklist caps the blocklist. Entries are keyed by client IP and
// otherwise only removed when that same address returns after its ban expires,
// so a scan from many sources would retain every one of them forever. At the
// cap we sweep expired entries first and, if that frees nothing, refuse to grow
// — a ban that cannot be recorded is far cheaper than an unbounded map fed by
// attacker-chosen keys.
const maxHoneypotBlocklist = 10_000

// defaultHoneypotPaths lists the trap paths used when deception is active but
// the operator configured none.
//
// Every entry must be a path no legitimate client ever requests. /admin and
// /wp-admin were deliberately removed: they are the front door of most admin
// panels and of every WordPress install, so trapping them by default bans the
// first real administrator to sign in — and behind CGNAT or a corporate egress,
// everyone sharing that address. Operators who front no such app can still add
// them explicitly via SecurityAdvanced.Deception.HoneypotPaths.
func defaultHoneypotPaths() []string {
	return []string{"/.env", "/.git", "/config.php", "/backup.sql", "/.aws", "/.ssh"}
}

// blockHoneypotIP records a ban, keeping the blocklist bounded.
//
// Loopback is never banned. The ban lasts 24 hours, lives only in memory, and
// has no expiry path other than waiting it out or restarting the process, so
// recording one against 127.0.0.1 takes out every local caller at once: health
// checks, the management API, and an administrator browsing the dashboard from
// the same host. That is a self-inflicted outage triggered by anything local
// touching a trap path, and it buys nothing — an attacker who can originate
// from loopback is already inside the machine. telemetry.RecordSecurityThreat
// drops loopback sources for the same reason.
//
// The request itself is still refused; only the durable ban is skipped.
func blockHoneypotIP(clientIP string, until time.Time) {
	if httputil.IsLoopback(clientIP) {
		return
	}

	blocklistMu.Lock()
	defer blocklistMu.Unlock()

	if _, exists := honeypotBlocklist[clientIP]; !exists && len(honeypotBlocklist) >= maxHoneypotBlocklist {
		now := time.Now()
		for ip, exp := range honeypotBlocklist {
			if now.After(exp) {
				delete(honeypotBlocklist, ip)
			}
		}
		if len(honeypotBlocklist) >= maxHoneypotBlocklist {
			return
		}
	}
	honeypotBlocklist[clientIP] = until
}

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
				paths = defaultHoneypotPaths()
			}

			path := r.URL.Path

			// Check for breadcrumb triggers first
			if strings.HasPrefix(path, "/_gateon_trap_") {
				recordHoneypotThreat(r, "dynamic_breadcrumb")
				blockHoneypotIP(clientIP, time.Now().Add(honeypotBanFor(clientIP, time.Now())))
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
					blockHoneypotIP(clientIP, time.Now().Add(honeypotBanFor(clientIP, time.Now())))

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

// Hijack forwards to the underlying writer so a WebSocket upgrade behind the
// honeypot breadcrumb middleware can take the raw connection. Breadcrumb
// injection only touches an HTML response body, which a hijacked connection
// does not have.
func (w *breadcrumbWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hj.Hijack()
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
	trapID := newTrapID()
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
					blockHoneypotIP(clientIP, time.Now().Add(honeypotBanFor(clientIP, time.Now())))

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
		Severity:    severityHigh,
		ActionTaken: actionBlocked,
	}))
}

// parseHoneypotConfig parses the middleware configuration into HoneypotConfig.
func parseHoneypotConfig(cfg map[string]string) HoneypotConfig {
	pathsStr := cfg["paths"]
	if pathsStr == "" {
		// Same default list as the global honeypot, and for the same reason:
		// a trap that bans an address for 24 hours must only cover paths no
		// legitimate client requests. See defaultHoneypotPaths.
		return HoneypotConfig{Paths: defaultHoneypotPaths()}
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

// newTrapID returns an unpredictable identifier for a breadcrumb trap path.
//
// crypto/rand rather than math/rand, and that is the point of the whole
// mechanism rather than a lint fix. A breadcrumb only works if an attacker
// cannot tell a trap path from a real one; with a predictable generator the
// sequence can be reproduced offline and every trap enumerated and avoided,
// which turns the deception layer into an oracle for exactly the visitors it
// exists to catch. The space is widened at the same time -- a million values is
// small enough to sweep.
func newTrapID() uint64 {
	var b [8]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		// crypto/rand does not fail in practice, and a trap that silently
		// became predictable would be worse than no trap. Fall back to a value
		// derived from the clock, which is still not enumerable offline.
		return uint64(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint64(b[:])
}
