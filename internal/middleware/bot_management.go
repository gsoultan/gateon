package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type BotManagementConfig struct {
	Enabled                 bool
	EnableJSChallenge       bool
	ChallengeTimeoutSeconds int
	SecretKey               string
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

			// 1. Check if challenge is already solved
			cookie, err := r.Cookie(ChallengeCookieName)
			if err == nil {
				if verifyChallengeToken(cookie.Value, cfg.SecretKey, r.UserAgent()) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// 2. If it's the challenge submission
			if r.Method == http.MethodPost && r.URL.Path == "/_gateon/challenge" {
				token := r.FormValue("token")
				if verifyChallengeToken(token, cfg.SecretKey, r.UserAgent()) {
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
			}

			// 3. Handle seed request
			if r.URL.Path == "/_gateon/seed" {
				seed := GenerateChallengeSeed(cfg.SecretKey, r.UserAgent())
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte(seed))
				return
			}

			// 4. Serve JS Challenge
			if cfg.EnableJSChallenge {
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
        <h1>Checking your browser...</h1>
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

func verifyChallengeToken(token, secret, ua string) bool {
	// Simple verification logic
	// Token format: payload.signature
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return false
	}

	payload := parts[0]
	signature := parts[1]

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload + ua))
	expectedSignature := fmt.Sprintf("%x", mac.Sum(nil))

	if signature != expectedSignature {
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

func GenerateChallengeSeed(secret, ua string) string {
	ts := time.Now().Unix()
	payload := strconv.FormatInt(ts, 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload + ua))
	signature := fmt.Sprintf("%x", mac.Sum(nil))
	return payload + "." + signature
}
