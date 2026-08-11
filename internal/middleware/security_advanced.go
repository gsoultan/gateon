// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/security/entropy"
	"github.com/gsoultan/gateon/internal/security/scanner"
	"github.com/gsoultan/gateon/internal/telemetry"
)

var xssScanner = scanner.NewScanner([]string{
	"<script", "javascript:", "onload=", "onerror=", "eval(", "atob(",
	"alert(", "prompt(", "confirm(", "<img", "<svg", "onerror",
	"document.cookie", "window.location",
})

var sqliScanner = scanner.NewScanner([]string{
	"union select", "select * from", "insert into", "update ", "delete from",
	"drop table", "truncate table", "information_schema", "--", "/*", "*/",
	" ' or 1=1", " \" or 1=1", "sleep(", "benchmark(", "pg_sleep(", "waitfor delay",
})

var genericAttackScanner = scanner.NewScanner([]string{
	"__proto__", "constructor.prototype", "constructor[prototype]",
	"() { :; }", "() { :;};", // Shellshock
	"${jndi:",                                                     // Log4Shell
	"class.module.classLoader",                                    // Spring4Shell
	"; cat /etc/passwd", "; id", "; whoami", "; curl ", "; wget ", // Shell Injection
	"coinhive.min.js", "authedmine.min.js", "cryptonight.wasm", // Malicious scripts
	"String.fromCharCode", "unescape(", "%u00", "eval(atob(", "navigator.sendBeacon", "new WebSocket(", "document.write(", "document.createElement('script')", // Malicious JS
})

var gamblingScanner = scanner.NewScanner([]string{
	"betting", "gambling", "casino", "slot machine", "poker", "sportsbook", "jackpot", "lottery", "bookmaker", "odds payout", "wagering", "baccarat", "blackjack", "roulette",
})

var phpScanner = scanner.NewScanner([]string{
	"<?php", "file_get_contents(", "include(", "require(", "eval(", "exec(", "system(", "passthru(", "shell_exec(", "base64_decode(", "$_GET", "$_POST", "$_REQUEST", "$_SERVER", "$_COOKIE", "$_FILES",
})

var fileUploadScanner = scanner.NewScanner([]string{
	".php", ".phtml", ".php3", ".php4", ".php5", ".phps", ".asp", ".aspx", ".jsp", ".jspx", ".sh", ".py", ".pl", ".exe", ".cgi", ".htaccess",
})

var securityBufferPool = sync.Pool{
	New: func() any {
		return bytes.NewBuffer(make([]byte, 0, 64*1024))
	},
}

// Tarpit middleware introduces progressive delays for suspicious clients based on fingerprint reputation.
func Tarpit(baseDelay, maxDelay time.Duration, scoreThreshold float64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fingerprint := telemetry.GetIPFingerprint(r)
			// Whitelist localhost and management traffic from tarpitting
			if httputil.IsLoopback(fingerprint) {
				next.ServeHTTP(w, r)
				return
			}
			reputation := telemetry.GetReputationScore(fingerprint)
			threatScore := 100.0 - reputation

			if threatScore >= scoreThreshold {
				delay := time.Duration(float64(baseDelay) * (threatScore / scoreThreshold))
				if delay > maxDelay {
					delay = maxDelay
				}
				if delay > 0 {
					time.Sleep(delay)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Entropy middleware calculates Shannon entropy of the request body.
// It uses a non-destructive read to avoid interfering with proxying.
func Entropy(threshold float64, routeID string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := request.GetClientIP(r, true)
			if httputil.IsLoopback(ip) {
				next.ServeHTTP(w, r)
				return
			}
			rs := request.GetRequestState(r)
			if rs != nil && rs.ExecutedEntropy {
				next.ServeHTTP(w, r)
				return
			}

			if r.Body != nil && r.Body != http.NoBody {
				// We limit entropy check to 1MB to avoid memory issues and latency
				limit := int64(1024 * 1024)
				// Use a TeeReader-like approach but we need the data before next.ServeHTTP
				// if we want to block, but here we only record threats.
				// To keep it non-destructive and simple:
				peeked, err := io.ReadAll(io.LimitReader(r.Body, limit))
				if err == nil && len(peeked) > 0 {
					// Restore body for downstream
					r.Body = struct {
						io.Reader
						io.Closer
					}{
						Reader: io.MultiReader(bytes.NewReader(peeked), r.Body),
						Closer: r.Body,
					}

					e := entropy.Calculate(peeked)
					if e > threshold {
						recordAdvancedThreat(r, "high_entropy_payload", (e-threshold)*20, fmt.Sprintf("High entropy payload detected: %.2f", e), routeID, "advanced", "HIGH", actionDetected)
					}
				}
				if rs != nil {
					rs.ExecutedEntropy = true
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func serveTrollResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	// Send an infinite stream of random-looking data
	// Using a static buffer to avoid allocations in the loop
	buf := make([]byte, 4096)
	for i := range buf {
		buf[i] = byte(i % 256)
	}

	for {
		if _, err := w.Write(buf); err != nil {
			return // Connection closed by client or other error
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		time.Sleep(100 * time.Millisecond) // Slow it down a bit to "hang" the tool longer
	}
}

func recordAdvancedThreat(r *http.Request, ttype string, score float64, details string, routeID string, category string, severity string, actionTaken string) {
	ip := request.GetClientIP(r, true)
	if httputil.IsLoopback(ip) {
		return
	}
	logger.SecurityEvent(ttype, r, details)
	telemetry.RecordSecurityThreat(telemetry.RecordSecurityThreatWithJA4(r, telemetry.SecurityThreat{
		ID:          fmt.Sprintf("adv-%s-%d", ttype, time.Now().UnixNano()),
		Type:        ttype,
		SourceIP:    request.GetClientIP(r, true),
		Score:       score,
		Details:     details,
		Time:        time.Now(),
		RouteID:     routeID,
		RequestURI:  r.RequestURI,
		Category:    category,
		Severity:    severity,
		ActionTaken: actionTaken,
		Method:      r.Method,
		UserAgent:   r.UserAgent(),
	}))
}

// XSSRecognition middleware scans request for common XSS patterns.
// This provides lightweight recognition without full WAF overhead.
func XSSRecognition(routeID string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := request.GetClientIP(r, true)
			if httputil.IsLoopback(ip) {
				next.ServeHTTP(w, r)
				return
			}
			rs := request.GetRequestState(r)
			if rs != nil && rs.ExecutedXSS {
				next.ServeHTTP(w, r)
				return
			}

			var details string
			found := false

			// Check query parameters (unescaped)
			if r.URL.RawQuery != "" {
				query, _ := url.QueryUnescape(r.URL.RawQuery)
				if matches := xssScanner.FindAll(query); len(matches) > 0 {
					found = true
					details = fmt.Sprintf("XSS pattern(s) '%s' found in query string", strings.Join(matches, ", "))
				}
			}

			// Check common headers
			if !found {
				for _, h := range []string{"User-Agent", "Referer", "X-Forwarded-For"} {
					val := r.Header.Get(h)
					if val == "" {
						continue
					}
					if matches := xssScanner.FindAll(val); len(matches) > 0 {
						found = true
						details = fmt.Sprintf("XSS pattern(s) '%s' found in header %s", strings.Join(matches, ", "), h)
						break
					}
				}
			}

			// Check body if small or if we can peek it safely
			if !found && r.Body != nil && r.Body != http.NoBody {
				buf := securityBufferPool.Get().(*bytes.Buffer)
				buf.Reset()
				defer securityBufferPool.Put(buf)

				// Peek up to 64KB
				peeked, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
				if err == nil && len(peeked) > 0 {
					// Restore body for downstream
					r.Body = struct {
						io.Reader
						io.Closer
					}{
						Reader: io.MultiReader(bytes.NewReader(peeked), r.Body),
						Closer: r.Body,
					}

					if matches := xssScanner.FindAll(string(peeked)); len(matches) > 0 {
						found = true
						details = fmt.Sprintf("XSS pattern(s) '%s' found in request body", strings.Join(matches, ", "))
					}
				}
			}

			if found {
				recordAdvancedThreat(r, "xss_detected", 50, details, routeID, "xss", "CRITICAL", actionDetected)
			}

			if rs != nil {
				rs.ExecutedXSS = true
			}

			next.ServeHTTP(w, r)
		})
	}
}

// SQLiRecognition middleware scans request for common SQLi patterns.
func SQLiRecognition(routeID string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := request.GetClientIP(r, true)
			if httputil.IsLoopback(ip) {
				next.ServeHTTP(w, r)
				return
			}
			rs := request.GetRequestState(r)
			if rs != nil && rs.ExecutedSQLI {
				next.ServeHTTP(w, r)
				return
			}

			var details string
			found := false

			if r.URL.RawQuery != "" {
				query, _ := url.QueryUnescape(r.URL.RawQuery)
				if matches := sqliScanner.FindAll(query); len(matches) > 0 {
					found = true
					details = fmt.Sprintf("SQLi pattern(s) '%s' found in query string", strings.Join(matches, ", "))
				}
			}

			if !found && r.Body != nil && r.Body != http.NoBody {
				peeked, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
				if err == nil && len(peeked) > 0 {
					r.Body = struct {
						io.Reader
						io.Closer
					}{
						Reader: io.MultiReader(bytes.NewReader(peeked), r.Body),
						Closer: r.Body,
					}

					if matches := sqliScanner.FindAll(string(peeked)); len(matches) > 0 {
						found = true
						details = fmt.Sprintf("SQLi pattern(s) '%s' found in request body", strings.Join(matches, ", "))
					}
				}
			}

			if found {
				recordAdvancedThreat(r, "sqli_detected", 60, details, routeID, "sqli", "CRITICAL", actionDetected)
			}

			if rs != nil {
				rs.ExecutedSQLI = true
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ThreatRecognition middleware scans request for various common attack patterns (RCE, Prototype Pollution, Gambling, PHP vuln, etc.)
func ThreatRecognition(routeID string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := request.GetClientIP(r, true)
			if httputil.IsLoopback(ip) {
				next.ServeHTTP(w, r)
				return
			}
			var details string
			found := false
			attackType := "generic_attack"
			severity := "HIGH"

			// Check common patterns in Query, Headers, and Body
			check := func(data string, source string) bool {
				if matches := genericAttackScanner.FindAll(data); len(matches) > 0 {
					found = true
					attackType = "generic_attack"
					severity = "HIGH"
					details = fmt.Sprintf("Attack pattern(s) '%s' found in %s", strings.Join(matches, ", "), source)
					return true
				}
				if matches := gamblingScanner.FindAll(data); len(matches) > 0 {
					found = true
					attackType = "gambling_detected"
					severity = "MEDIUM"
					details = fmt.Sprintf("Gambling related pattern(s) '%s' found in %s", strings.Join(matches, ", "), source)
					return true
				}
				if matches := phpScanner.FindAll(data); len(matches) > 0 {
					found = true
					attackType = "php_vulnerability"
					severity = "CRITICAL"
					details = fmt.Sprintf("PHP vulnerability pattern(s) '%s' found in %s", strings.Join(matches, ", "), source)
					return true
				}
				if matches := fileUploadScanner.FindAll(data); len(matches) > 0 {
					// Only flag if it looks like a filename in a relevant place
					if strings.Contains(source, "query string") || strings.Contains(source, "body") {
						found = true
						attackType = "file_upload_attempt"
						severity = "CRITICAL"
						details = fmt.Sprintf("Malicious file extension(s) '%s' found in %s", strings.Join(matches, ", "), source)
						return true
					}
				}
				return false
			}

			if r.URL.RawQuery != "" {
				query, _ := url.QueryUnescape(r.URL.RawQuery)
				check(query, "query string")
			}

			if !found {
				for _, h := range []string{"User-Agent", "Referer", "X-Forwarded-For"} {
					if val := r.Header.Get(h); val != "" {
						if check(val, "header "+h) {
							break
						}
					}
				}
			}

			if !found && r.Body != nil && r.Body != http.NoBody {
				peeked, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
				if err == nil && len(peeked) > 0 {
					r.Body = struct {
						io.Reader
						io.Closer
					}{
						Reader: io.MultiReader(bytes.NewReader(peeked), r.Body),
						Closer: r.Body,
					}
					check(string(peeked), "request body")
				}
			}

			if found {
				recordAdvancedThreat(r, attackType, 70, details, routeID, "advanced", severity, actionDetected)
			}

			next.ServeHTTP(w, r)
		})
	}
}
