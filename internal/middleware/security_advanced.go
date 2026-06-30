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

var securityBufferPool = sync.Pool{
	New: func() any {
		return bytes.NewBuffer(make([]byte, 0, 64*1024))
	},
}

// Tarpit middleware introduces progressive delays for suspicious IPs.
func Tarpit(baseDelay, maxDelay time.Duration, scoreThreshold float64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := request.GetClientIP(r, true)
			score := telemetry.GetIPThreatScore(ip)

			if score >= scoreThreshold {
				delay := time.Duration(float64(baseDelay) * (score / scoreThreshold))
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
						recordAdvancedThreat(r, "high_entropy_payload", (e-threshold)*20, fmt.Sprintf("High entropy payload detected: %.2f", e), routeID)
					}
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

func recordAdvancedThreat(r *http.Request, ttype string, score float64, details string, routeID string) {
	logger.SecurityEvent(ttype, r, details)
	telemetry.RecordSecurityThreat(telemetry.SecurityThreat{
		ID:         fmt.Sprintf("adv-%s-%d", ttype, time.Now().UnixNano()),
		Type:       ttype,
		SourceIP:   request.GetClientIP(r, true),
		Score:      score,
		Details:    details,
		Time:       time.Now(),
		RouteID:    routeID,
		RequestURI: r.URL.Path,
		Category:   "xss", // Default to xss category for XSS threats
	})
}

// XSSRecognition middleware scans request for common XSS patterns.
// This provides lightweight recognition without full WAF overhead.
func XSSRecognition(routeID string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
				recordAdvancedThreat(r, "xss_detected", 50, details, routeID)
			}

			next.ServeHTTP(w, r)
		})
	}
}
