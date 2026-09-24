// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/kind"
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

func BotManagement(cfg BotManagementConfig) kind.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serveBotManagement(cfg, next, w, r)
		})
	}
}

func serveBotManagement(cfg BotManagementConfig, next http.Handler, w http.ResponseWriter, r *http.Request) {
	if !cfg.Enabled || kind.IsCorsPreflight(r) {
		next.ServeHTTP(w, r)
		return
	}

	clientIP := request.GetClientIP(r, config.EffectiveTrustCloudflare())

	// 1. Check browser integrity
	if cfg.EnableBrowserIntegrity && !checkBrowserIntegrity(r) {
		logger.SecurityEvent("bot_detected_integrity", r, "failed browser integrity check")
		recordBotThreat(r, cfg, clientIP, "integrity", 40,
			"Failed browser integrity check (Sec-Fetch headers)", kind.SeverityMedium)
		http.Error(w, "Forbidden - Browser Integrity Check Failed", http.StatusForbidden)
		return
	}

	// 2. Check if challenge is already solved
	if cookie, err := r.Cookie(ChallengeCookieName); err == nil &&
		verifyPass(cookie.Value, cfg.SecretKey, r.UserAgent(), clientIP, time.Now(), passLifetime(cfg)) {
		next.ServeHTTP(w, r)
		return
	}

	// 3. If it's the challenge submission
	if r.Method == http.MethodPost && r.URL.Path == "/_gateon/challenge" {
		if handleChallengeSubmission(cfg, clientIP, w, r) {
			return
		}
	}

	// 4. Handle seed request
	if r.URL.Path == "/_gateon/seed" {
		seed := GenerateChallengeSeed(cfg.SecretKey, r.UserAgent(), clientIP)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(seed))
		return
	}

	// 5. Serve JS Challenge
	if cfg.EnableJSChallenge {
		telemetry.MiddlewareBotManagementTotal.WithLabelValues(cfg.RouteID, "challenge_served").Inc()
		telemetry.ActiveUnverifiedClientsTotal.Inc()
		serveJSChallenge(w, r)
		return
	}

	next.ServeHTTP(w, r)
}

// handleChallengeSubmission verifies a posted challenge token. It reports
// whether it answered the request: a valid token sets the bypass cookie and
// redirects, an invalid one is recorded and falls through to be re-challenged
// rather than being served.
func handleChallengeSubmission(cfg BotManagementConfig, clientIP string, w http.ResponseWriter, r *http.Request) bool {
	now := time.Now()
	if !verifySeed(r.FormValue("token"), cfg.SecretKey, r.UserAgent(), clientIP, now) {
		telemetry.ActiveUnverifiedClientsTotal.Dec()
		recordBotThreat(r, cfg, clientIP, "challenge-fail", 60,
			"Failed JavaScript challenge submission", kind.SeverityHigh)
		return false
	}

	telemetry.MiddlewareBotManagementTotal.WithLabelValues(cfg.RouteID, "challenge_solved").Inc()
	telemetry.ActiveUnverifiedClientsTotal.Dec()
	// This cookie is the proof that the client solved the bot
	// challenge, so it is a bypass credential and gets the same
	// attributes as a session cookie. Secure comes from
	// request.IsSecure rather than r.TLS: behind a TLS-terminating
	// proxy r.TLS is nil, and the attribute would be dropped in
	// exactly the deployments where the token is most exposed.
	// #nosec G124 -- Secure is set from the resolved scheme just
	// below; gosec cannot see through the variable.
	http.SetCookie(w, &http.Cookie{
		Name:     ChallengeCookieName,
		Value:    passFor(cfg.SecretKey, r.UserAgent(), clientIP, now),
		Path:     "/",
		HttpOnly: true,
		Secure:   request.IsSecure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   cfg.ChallengeTimeoutSeconds,
	})
	// #nosec G710 -- safeRedirectTarget rejects any scheme, host or opaque form
	// and requires a leading "/" while rejecting "//" and "/\\", testing the
	// decoded path so a percent-encoded backslash cannot slip past.
	http.Redirect(w, r, safeRedirectTarget(r.FormValue("redirect")), http.StatusFound)
	return true
}

// recordBotThreat files one bot-management refusal for the dashboard.
func recordBotThreat(r *http.Request, cfg BotManagementConfig, clientIP, label string, score float64, details, severity string) {
	telemetry.RecordSecurityThreat(telemetry.RecordSecurityThreatWithJA4(r, telemetry.SecurityThreat{
		ID:          fmt.Sprintf("bot-%s-%s-%s", label, cfg.RouteID, clientIP),
		Type:        "bot_detected",
		SourceIP:    clientIP,
		Score:       score,
		Details:     details,
		Time:        time.Now(),
		RouteID:     cfg.RouteID,
		RequestURI:  r.URL.RequestURI(),
		Category:    "bot",
		Severity:    severity,
		ActionTaken: kind.ActionBlocked,
	}))
}

// safeRedirectTarget reduces a redirect target to a path that cannot leave this
// origin, falling back to "/" for anything it cannot vouch for.
//
// The challenge page round-trips the original URL through the client, so by the
// time it comes back as a form value it is attacker-controlled. Handing that
// straight to http.Redirect turns the challenge into an open redirect that
// borrows the gateway's own domain to launder a phishing link — worse here than
// in most places, because the victim reaches it by passing a security check.
//
// A leading-slash test is not enough on its own: browsers read "//evil.com" as
// protocol-relative, and some normalise the backslash in "/\evil.com" to a
// second slash and do the same. Parsing and then rejecting anything carrying a
// scheme or host covers both without guessing at browser quirks.
func safeRedirectTarget(raw string) string {
	if raw == "" {
		return "/"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Opaque != "" {
		return "/"
	}
	// Test the decoded path, not the escaped one: EscapedPath percent-encodes
	// the backslash to %5C, which would slip past a check written against the
	// escaped form even though the input is plainly an attempt at
	// protocol-relative.
	if !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") || strings.HasPrefix(u.Path, `/\`) {
		return "/"
	}
	p := u.EscapedPath()
	if u.RawQuery != "" {
		return p + "?" + u.RawQuery
	}
	return p
}

func serveJSChallenge(w http.ResponseWriter, r *http.Request) {
	nonce := kind.GenerateNonce()

	// Escape before interpolating: this lands in a double-quoted HTML attribute
	// and the request URI is entirely attacker-chosen, so a path of
	// `/"><base href="https://evil.com/">` would otherwise close the attribute
	// and repoint every relative URL on the page — including the form action
	// and the seed fetch — at the attacker. The CSP below blocks injected
	// inline script, but it does not stop <base>, <meta refresh> or a
	// substituted form, so the escape is the actual fix and the CSP is
	// defence in depth. RequestURI() rather than String() keeps any scheme or
	// host out of the value to begin with.
	redirectTo := html.EscapeString(safeRedirectTarget(r.URL.RequestURI()))

	// A simple stealthy JS challenge.
	// In a real implementation, this would be more complex and obfuscated.
	page := fmt.Sprintf(`
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
    <script nonce="%s">
        (function() {
            // Simple proof of work or just a delay to foil simple scrapers
            // The seed is only redeemable once it has aged past the
            // gateway's minimum solve time, so wait after fetching it.
            fetch('/_gateon/seed').then(r => r.text()).then(seed => {
                document.getElementById('token').value = seed;
                setTimeout(function() {
                    document.getElementById('challenge-form').submit();
                }, 2000);
            });
        })();
    </script>
</body>
</html>`, redirectTo, nonce)

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Content-Security-Policy", fmt.Sprintf("default-src 'self'; script-src 'self' 'nonce-%s'; style-src 'self' 'unsafe-inline';", nonce))
	w.WriteHeader(http.StatusForbidden) // Or 403 to indicate challenge required
	_, _ = w.Write([]byte(page))
}

// The seed and the pass are two different tokens, signed in two different
// contexts, and the only way from one to the other is POST /_gateon/challenge.
//
// They used to be one token. The page fetched /_gateon/seed and posted it back,
// and the value it fetched was exactly what the cookie check accepted, so any
// client could skip the page: fetch the seed and send it as the cookie, one
// request, no JavaScript. The MAC also ran the timestamp, User-Agent and IP
// together with no separators, so a client whose User-Agent began with digits
// was handed a valid signature for a timestamp centuries ahead, and future
// timestamps were never refused.
const (
	seedContext = "gateon-bot-seed-v2"
	passContext = "gateon-bot-pass-v2"
	// minSolveTime is how long a seed must age before it is redeemed; the
	// challenge page waits two seconds after fetching it.
	minSolveTime = 1500 * time.Millisecond
	// seedLifetime bounds how long a fetched seed stays redeemable.
	seedLifetime = 5 * time.Minute
	// clockSkew is how far ahead of this gateway's clock a token's issue time
	// may be; in a cluster another instance may have issued it.
	clockSkew = 5 * time.Second
	// defaultPassLifetime is used when the route configures no timeout.
	defaultPassLifetime = time.Hour
)

// GenerateChallengeSeed returns the seed the challenge page fetches.
func GenerateChallengeSeed(secret, ua, ip string) string {
	return seedFor(secret, ua, ip, time.Now())
}

func seedFor(secret, ua, ip string, at time.Time) string {
	return signBotToken(seedContext, secret, ua, ip, at)
}

func passFor(secret, ua, ip string, at time.Time) string {
	return signBotToken(passContext, secret, ua, ip, at)
}

func passLifetime(cfg BotManagementConfig) time.Duration {
	if cfg.ChallengeTimeoutSeconds > 0 {
		return time.Duration(cfg.ChallengeTimeoutSeconds) * time.Second
	}
	return defaultPassLifetime
}

// signBotToken returns "<issued unix ms>.<hex MAC>". Every field is written
// length-prefixed, so no field can borrow bytes from its neighbour.
func signBotToken(context, secret, ua, ip string, at time.Time) string {
	issued := strconv.FormatInt(at.UnixMilli(), 10)
	return issued + "." + hex.EncodeToString(botMAC(context, secret, issued, ua, ip))
}

func botMAC(context, secret string, fields ...string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	for _, f := range append([]string{context}, fields...) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(f)))
		_, _ = mac.Write(n[:])
		_, _ = io.WriteString(mac, f)
	}
	return mac.Sum(nil)
}

// tokenAge checks token's MAC in context and returns how long ago it was
// issued. A token issued in the future, beyond clock skew, is invalid.
func tokenAge(context, token, secret, ua, ip string, now time.Time) (time.Duration, bool) {
	issued, sig, ok := strings.Cut(token, ".")
	if !ok || len(sig) != hex.EncodedLen(sha256.Size) {
		return 0, false
	}
	var got [sha256.Size]byte
	if _, err := hex.Decode(got[:], []byte(sig)); err != nil {
		return 0, false
	}
	if subtle.ConstantTimeCompare(got[:], botMAC(context, secret, issued, ua, ip)) != 1 {
		return 0, false
	}
	ms, err := strconv.ParseInt(issued, 10, 64)
	if err != nil {
		return 0, false
	}
	age := now.Sub(time.UnixMilli(ms))
	return age, age >= -clockSkew
}

func verifySeed(seed, secret, ua, ip string, now time.Time) bool {
	age, ok := tokenAge(seedContext, seed, secret, ua, ip, now)
	return ok && age >= minSolveTime && age <= seedLifetime
}

func verifyPass(token, secret, ua, ip string, now time.Time, lifetime time.Duration) bool {
	age, ok := tokenAge(passContext, token, secret, ua, ip, now)
	return ok && age <= lifetime
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
