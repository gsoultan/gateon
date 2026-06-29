package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

type BotManagementConfig struct {
	Enabled                 bool
	EnableJSChallenge       bool
	EnableBrowserIntegrity  bool
	ChallengeTimeoutSeconds int
	SecretKey               string
	RouteID                 string
}

const (
	ChallengeCookieName = "gateon_bot_challenge"
)

func BotManagement(cfg BotManagementConfig) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			clientIP := request.GetClientIP(r, config.EffectiveTrustCloudflare())

			// 1. Check browser integrity
			if cfg.EnableBrowserIntegrity {
				if !checkBrowserIntegrity(r) {
					logger.SecurityEvent("bot_detected_integrity", r, "failed browser integrity check")
					telemetry.MiddlewareBotManagementTotal.WithLabelValues(cfg.RouteID, "integrity_failed").Inc()
					telemetry.BotMitigationTotal.WithLabelValues("integrity_fail").Inc()

					telemetry.RecordSecurityThreat(telemetry.SecurityThreat{
						ID:          fmt.Sprintf("bot-integrity-%s-%s", cfg.RouteID, clientIP),
						Type:        "bot_detected",
						SourceIP:    clientIP,
						Score:       40,
						Details:     "Failed browser integrity check (Sec-Fetch headers)",
						Time:        time.Now(),
						RouteID:     cfg.RouteID,
						RequestURI:  r.URL.RequestURI(),
						Category:    "bot",
						Severity:    "medium",
						ActionTaken: "blocked",
					})

					http.Error(w, "Forbidden - Browser Integrity Check Failed", http.StatusForbidden)
					return
				}
			}

			// 2. Check if challenge is already solved
			cookie, err := r.Cookie(ChallengeCookieName)
			if err == nil {
				if verifyChallengeToken(cookie.Value, cfg.SecretKey, r.UserAgent(), clientIP) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// 2. If it's the challenge submission
			if r.Method == http.MethodPost && r.URL.Path == "/_gateon/challenge" {
				token := r.FormValue("token")
				if verifyChallengeToken(token, cfg.SecretKey, r.UserAgent(), clientIP) {
					telemetry.MiddlewareBotManagementTotal.WithLabelValues(cfg.RouteID, "challenge_solved").Inc()
					telemetry.ActiveUnverifiedClientsTotal.Dec()
					http.SetCookie(w, &http.Cookie{
						Name:     ChallengeCookieName,
						Value:    token,
						Path:     "/",
						HttpOnly: true,
						MaxAge:   cfg.ChallengeTimeoutSeconds,
					})
					http.Redirect(w, r, r.FormValue("redirect"), http.StatusFound)
					return
				}
				telemetry.MiddlewareBotManagementTotal.WithLabelValues(cfg.RouteID, "challenge_failed").Inc()
				telemetry.BotMitigationTotal.WithLabelValues("js_challenge_fail").Inc()
				telemetry.ActiveUnverifiedClientsTotal.Dec()
				telemetry.RecordSecurityThreat(telemetry.SecurityThreat{
					ID:          fmt.Sprintf("bot-challenge-fail-%s-%s", cfg.RouteID, clientIP),
					Type:        "bot_detected",
					SourceIP:    clientIP,
					Score:       60,
					Details:     "Failed JavaScript challenge submission",
					Time:        time.Now(),
					RouteID:     cfg.RouteID,
					RequestURI:  r.URL.RequestURI(),
					Category:    "bot",
					Severity:    "high",
					ActionTaken: "blocked",
				})
			}

			// 3. Handle seed request
			if r.URL.Path == "/_gateon/seed" {
				seed := GenerateChallengeSeed(cfg.SecretKey, r.UserAgent(), clientIP)
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte(seed))
				return
			}

			// 4. Serve JS Challenge
			if cfg.EnableJSChallenge {
				telemetry.MiddlewareBotManagementTotal.WithLabelValues(cfg.RouteID, "challenge_served").Inc()
				telemetry.ActiveUnverifiedClientsTotal.Inc()
				serveJSChallenge(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func serveJSChallenge(w http.ResponseWriter, r *http.Request) {
	// A simple stealthy JS challenge.
	// In a real implementation, this would be more complex and obfuscated.
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>Just a moment...</title>
    <style>
        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f4f4f4; }
        .container { text-align: center; background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Challenge</h1>
        <p>Please wait while we verify your request.</p>
        <form id="challenge-form" method="POST" action="/_gateon/challenge">
            <input type="hidden" name="token" id="token">
            <input type="hidden" name="redirect" value="%s">
        </form>
    </div>
    <script>
        (function() {
            // Simple proof of work or just a delay to foil simple scrapers
            setTimeout(function() {
                var ua = navigator.userAgent;
                var ts = Math.floor(Date.now() / 1000);
                // We'd normally get a seed from the server to prevent replay
                // For now, we'll just simulate a token generation
                // Real implementation would use an XHR to get a signed seed
                fetch('/_gateon/seed').then(r => r.text()).then(seed => {
                    document.getElementById('token').value = seed;
                    document.getElementById('challenge-form').submit();
                });
            }, 2000);
        })();
    </script>
</body>
</html>`, r.URL.String())

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusForbidden) // Or 403 to indicate challenge required
	_, _ = w.Write([]byte(html))
}

func verifyChallengeToken(token, secret, ua, ip string) bool {
	// Simple verification logic
	// Token format: payload.signature
	payload, signature, ok := strings.Cut(token, ".")
	if !ok {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = io.WriteString(mac, payload)
	_, _ = io.WriteString(mac, ua)
	_, _ = io.WriteString(mac, ip)
	expectedSignature := mac.Sum(nil)

	// signature is hex encoded, let's decode it safely
	if len(signature) != hex.EncodedLen(len(expectedSignature)) {
		return false
	}

	var sigBuf [32]byte // sha256 is 32 bytes
	sigBytes := sigBuf[:]
	n, err := hex.Decode(sigBytes, []byte(signature))
	if err != nil || n != len(expectedSignature) || subtle.ConstantTimeCompare(sigBytes, expectedSignature) != 1 {
		return false
	}

	// Verify timestamp in payload
	tsStr := payload
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}

	// Token valid for 2 hours
	if time.Since(time.Unix(ts, 0)) > 2*time.Hour {
		return false
	}

	return true
}

func GenerateChallengeSeed(secret, ua, ip string) string {
	ts := time.Now().Unix()
	payload := strconv.FormatInt(ts, 10)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = io.WriteString(mac, payload)
	_, _ = io.WriteString(mac, ua)
	_, _ = io.WriteString(mac, ip)
	signature := hex.EncodeToString(mac.Sum(nil))
	return payload + "." + signature
}

func checkBrowserIntegrity(r *http.Request) bool {
	ua := r.UserAgent()
	if ua == "" {
		return false
	}

	lowerUA := strings.ToLower(ua)
	isBrowser := strings.Contains(lowerUA, "mozilla") ||
		strings.Contains(lowerUA, "chrome") ||
		strings.Contains(lowerUA, "safari") ||
		strings.Contains(lowerUA, "edge")

	if !isBrowser {
		return true // Skip for non-browser-like UAs (APIs)
	}

	// Modern browsers should have Sec-Fetch headers
	// If it's a modern browser UA but missing these, it's likely a script
	if strings.Contains(lowerUA, "chrome/") || strings.Contains(lowerUA, "edge/") || strings.Contains(lowerUA, "safari/") {
		fetchSite := r.Header.Get("Sec-Fetch-Site")
		fetchMode := r.Header.Get("Sec-Fetch-Mode")
		fetchDest := r.Header.Get("Sec-Fetch-Dest")

		if fetchSite == "" && fetchMode == "" && fetchDest == "" {
			// Suspicious: claims to be a modern browser but lacks fetch metadata
			return false
		}
	}

	return true
}
