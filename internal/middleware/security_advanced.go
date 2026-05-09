package middleware

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// DeceptionConfig defines configuration for Deception middleware.
type DeceptionConfig struct {
	HoneypotPaths        []string
	InjectInvisibleLinks bool
	InvisibleLinkPaths   []string
	RouteID              string
	EnableTrollResponse  bool
	CanaryHeader         string // attractive-looking header name
	CanaryToken          string // attractive-looking header value
}

// Deception middleware provides path honeypots and invisible link injection.
func Deception(cfg DeceptionConfig) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path

			// 1. Check for Canary Token reuse
			if cfg.CanaryHeader != "" && cfg.CanaryToken != "" {
				if r.Header.Get(cfg.CanaryHeader) == cfg.CanaryToken {
					recordAdvancedThreat(r, "canary_token_reused", 100, "Attacker reused injected canary header: "+cfg.CanaryHeader, cfg.RouteID)
					if cfg.EnableTrollResponse {
						serveTrollResponse(w)
					} else {
						http.Error(w, "Forbidden", http.StatusForbidden)
					}
					return
				}
			}

			// 2. Check for honeypot path access
			for _, trap := range cfg.HoneypotPaths {
				if trap != "" && (path == trap || strings.HasPrefix(path, trap+"/")) {
					recordAdvancedThreat(r, "honeypot_triggered", 100, "Access to trap path: "+trap, cfg.RouteID)
					if cfg.EnableTrollResponse {
						serveTrollResponse(w)
					} else {
						http.Error(w, "Forbidden", http.StatusForbidden)
					}
					return
				}
			}

			// 3. Check for invisible link access
			for _, link := range cfg.InvisibleLinkPaths {
				if link != "" && path == link {
					recordAdvancedThreat(r, "deception_link_triggered", 100, "Access to invisible deception link: "+link, cfg.RouteID)
					if cfg.EnableTrollResponse {
						serveTrollResponse(w)
					} else {
						http.Error(w, "Forbidden", http.StatusForbidden)
					}
					return
				}
			}

			// 4. Inject Canary Header into outbound request (to be attractive to attackers sniffing)
			if cfg.CanaryHeader != "" && cfg.CanaryToken != "" {
				// We don't want to break the backend, so this is mostly for the response if possible.
				// But the recommendation says "Inject a fake, attractive-looking header".
				// Let's inject it into the response headers instead so the attacker sees it.
				w.Header().Set(cfg.CanaryHeader, cfg.CanaryToken)
			}

			if !cfg.InjectInvisibleLinks || len(cfg.InvisibleLinkPaths) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			// Wrap response to inject invisible links if it's HTML
			drw := &deceptionResponseWriter{
				ResponseWriter: w,
				links:          cfg.InvisibleLinkPaths,
			}
			next.ServeHTTP(drw, r)
		})
	}
}

type deceptionResponseWriter struct {
	http.ResponseWriter
	links       []string
	wroteHeader bool
}

func (w *deceptionResponseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	contentType := w.Header().Get("Content-Type")
	if code == http.StatusOK && strings.Contains(contentType, "text/html") {
		w.Header().Del("Content-Length")
	}
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *deceptionResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	contentType := w.Header().Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		if idx := bytes.LastIndex(b, []byte("</body>")); idx != -1 {
			var sb strings.Builder
			for _, link := range w.links {
				_, _ = fmt.Fprintf(&sb, `<a href="%s" style="display:none" aria-hidden="true" rel="nofollow"></a>`, link)
			}
			injection := []byte(sb.String())

			newB := make([]byte, 0, len(b)+len(injection))
			newB = append(newB, b[:idx]...)
			newB = append(newB, injection...)
			newB = append(newB, b[idx:]...)

			_, err := w.ResponseWriter.Write(newB)
			return len(b), err
		}
	}

	return w.ResponseWriter.Write(b)
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

// Pow middleware serves a cryptographic challenge to suspicious IPs.
func Pow(difficulty int, scoreThreshold float64, secret string, routeID string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := request.GetClientIP(r, true)
			score := telemetry.GetIPThreatScore(ip)

			if score < scoreThreshold {
				next.ServeHTTP(w, r)
				return
			}

			// Check for valid challenge token in cookie
			cookie, err := r.Cookie("gateon_pow_token")
			if err == nil && validatePowToken(cookie.Value, ip, difficulty, secret) {
				next.ServeHTTP(w, r)
				return
			}

			// If it's a solution submission (POST with token)
			if r.Method == http.MethodPost && r.FormValue("pow_solution") != "" {
				solution := r.FormValue("pow_solution")
				nonce := r.FormValue("pow_nonce")
				if verifySolution(ip, nonce, solution, difficulty) {
					token := generatePowToken(ip, difficulty, secret)
					http.SetCookie(w, &http.Cookie{
						Name:     "gateon_pow_token",
						Value:    token,
						Path:     "/",
						HttpOnly: true,
						MaxAge:   3600,
					})
					// Redirect back to same page to retry original request
					http.Redirect(w, r, r.RequestURI, http.StatusSeeOther)
					return
				}
			}

			// Serve the challenge page
			serveChallengePage(w, ip, difficulty)
		})
	}
}

func generatePowToken(ip string, difficulty int, secret string) string {
	h := sha256.New()
	h.Write([]byte(ip + strconv.Itoa(difficulty) + secret))
	return hex.EncodeToString(h.Sum(nil))
}

func validatePowToken(token, ip string, difficulty int, secret string) bool {
	return token == generatePowToken(ip, difficulty, secret)
}

func verifySolution(ip, nonce, solution string, difficulty int) bool {
	h := sha256.New()
	h.Write([]byte(ip + nonce + solution))
	hash := hex.EncodeToString(h.Sum(nil))
	prefix := strings.Repeat("0", difficulty)
	return strings.HasPrefix(hash, prefix)
}

func serveChallengePage(w http.ResponseWriter, ip string, difficulty int) {
	nonce := strconv.FormatInt(time.Now().UnixNano(), 10)
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Security Check - Gateon</title>
    <style>
        body { font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: #f4f7f9; }
        .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); text-align: center; max-width: 400px; }
        h1 { color: #1e293b; margin-bottom: 1rem; }
        p { color: #64748b; line-height: 1.5; }
        .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #3b82f6; border-radius: 50%%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 2rem auto; }
        @keyframes spin { 0%% { transform: rotate(0deg); } 100%% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="card">
        <h1>Security Check</h1>
        <p>Please wait while we verify your connection. This will only take a few seconds.</p>
        <div class="spinner"></div>
        <form id="pow-form" method="POST">
            <input type="hidden" name="pow_nonce" value="%s">
            <input type="hidden" name="pow_solution" id="pow-solution">
        </form>
    </div>
    <script>
        async function solve() {
            const ip = "%s";
            const nonce = "%s";
            const difficulty = %d;
            const prefix = "0".repeat(difficulty);
            let solution = 0;
            while (true) {
                const msg = ip + nonce + solution;
                const buf = new TextEncoder().encode(msg);
                const hashBuf = await crypto.subtle.digest('SHA-256', buf);
                const hashArray = Array.from(new Uint8Array(hashBuf));
                const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                if (hashHex.startsWith(prefix)) {
                    document.getElementById('pow-solution').value = solution;
                    document.getElementById('pow-form').submit();
                    break;
                }
                solution++;
                if (solution %% 1000 === 0) await new Promise(r => setTimeout(r, 0));
            }
        }
        solve();
    </script>
</body>
</html>`, nonce, ip, nonce, difficulty)

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(html))
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
