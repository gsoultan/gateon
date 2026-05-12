package middleware

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
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
					e := calculateEntropy(body)
					if e > threshold {
						recordAdvancedThreat(r, "high_entropy_payload", (e-threshold)*20, fmt.Sprintf("High entropy payload detected: %.2f", e), routeID)
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	counts := make([]int, 256)
	for _, b := range data {
		counts[b]++
	}
	var entropy float64
	invLen := 1.0 / float64(len(data))
	for _, count := range counts {
		if count > 0 {
			p := float64(count) * invLen
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
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
	})
}
