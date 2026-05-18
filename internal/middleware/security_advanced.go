package middleware

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/security/entropy"
	"github.com/gsoultan/gateon/internal/telemetry"
)

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
func Entropy(threshold float64, routeID string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > 0 && r.ContentLength < 1024*1024 {
				body, err := io.ReadAll(r.Body)
				if err == nil {
					r.Body = io.NopCloser(bytes.NewBuffer(body))
					e := entropy.Calculate(body)
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
	keywords := []string{
		"<script", "javascript:", "onload=", "onerror=", "eval(", "atob(",
		"alert(", "prompt(", "confirm(", "<img", "<svg", "onerror",
		"document.cookie", "window.location",
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			found := false
			var details string

			// Check query parameters
			query, _ := url.QueryUnescape(r.URL.RawQuery)
			query = strings.ToLower(query)
			for _, k := range keywords {
				if strings.Contains(query, k) {
					found = true
					details = fmt.Sprintf("XSS pattern '%s' found in query string", k)
					break
				}
			}

			// Check common headers
			if !found {
				for _, h := range []string{"User-Agent", "Referer", "X-Forwarded-For"} {
					val := strings.ToLower(r.Header.Get(h))
					for _, k := range keywords {
						if strings.Contains(val, k) {
							found = true
							details = fmt.Sprintf("XSS pattern '%s' found in header %s", k, h)
							break
						}
					}
					if found {
						break
					}
				}
			}

			// Check body if small
			if !found && r.ContentLength > 0 && r.ContentLength < 64*1024 {
				body, err := io.ReadAll(r.Body)
				if err == nil {
					r.Body = io.NopCloser(bytes.NewBuffer(body))
					bodyLower := strings.ToLower(string(body))
					for _, k := range keywords {
						if strings.Contains(bodyLower, k) {
							found = true
							details = fmt.Sprintf("XSS pattern '%s' found in request body", k)
							break
						}
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
