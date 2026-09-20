// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/security/mitigation"
	"github.com/gsoultan/gateon/internal/telemetry"
)

const (
	PowHeaderChallenge = "X-Gateon-Pow-Challenge"
	PowHeaderSolution  = "X-Gateon-Pow-Solution"
	PowNonceHeader     = "X-Gateon-Pow-Nonce"
	// PowHeaderID carries the challenge identifier a solution answers.
	PowHeaderID = "X-Gateon-Pow-ID"

	// powChallengeTTL is how long an issued challenge stays answerable. There
	// is no per-challenge store, so a solution can be replayed within this
	// window; the window is what bounds the replay.
	powChallengeTTL = 5 * time.Minute
	// powClockSkew is how far ahead of this instance's clock an ID may be dated
	// before it is refused. Slightly ahead is another instance's clock; a year
	// ahead is a client choosing a timestamp the expiry check can never reach.
	powClockSkew = time.Minute
	// powMACLen is the hex length the challenge MAC is truncated to (128 bits).
	powMACLen = 32
)

// generatedPowKey is the per-process key for routes that configure no secret.
//
// The router refuses to install the middleware without a secret, but the
// route-level factory does not, and a challenge signed with an empty key is
// one anyone can sign. As with the bot-management fallback, the cost is that
// challenges do not survive a restart and are not shared between instances.
var (
	generatedPowKeyOnce sync.Once
	generatedPowKey     []byte
)

func powKey(secret string) []byte {
	if secret != "" {
		return []byte(secret)
	}
	generatedPowKeyOnce.Do(func() {
		b := make([]byte, 32)
		if _, err := cryptorand.Read(b); err != nil {
			logger.L.LogError("cannot generate a proof-of-work key; routes without a secret will "+
				"challenge every request and accept no solution", "error", err)
			return
		}
		generatedPowKey = b
		logger.L.LogWarn("proof-of-work route has no secret; generated a random key for this process. " +
			"Challenges will not survive a restart and are not shared between instances.")
	})
	return generatedPowKey
}

// powChallenge issues and verifies proof-of-work challenges for one route.
type powChallenge struct {
	key        []byte
	difficulty int
}

// Pow checks if a client needs to solve a cryptographic challenge.
func Pow(difficulty int, threshold float64, secret string, routeID string) Middleware {
	pc := powChallenge{key: powKey(secret), difficulty: difficulty}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip for internal paths, if difficulty is 0, or for an allowlisted
			// source. A proof-of-work challenge is an active mitigation: it costs
			// the client a round trip and CPU, and an API client or monitoring
			// probe the operator has vouched for cannot solve one at all.
			if IsInternalPath(r.URL.Path) || difficulty <= 0 ||
				mitigation.IsAllowlisted(telemetry.ClientIPOf(r)) {
				next.ServeHTTP(w, r)
				return
			}

			// Scoped to the client's network, not the browser class: a challenge
			// served because someone else's score is bad is a false positive that
			// costs every user of that browser a round trip.
			repID := telemetry.GetReputationID(r)
			score := telemetry.GetReputationScore(repID)

			// If reputation is below threshold, require PoW.
			if score < threshold {
				if r.Header.Get(PowHeaderSolution) != "" && r.Header.Get(PowNonceHeader) != "" {
					if pc.verify(r) {
						// Solution correct, proceed.
						next.ServeHTTP(w, r)
						return
					}
					// Invalid solution - record as a threat
					recordAdvancedThreat(r, "pow_invalid_solution", 10.0, "Invalid PoW solution provided", routeID, "bot", "MEDIUM", "challenged")
				}

				// Otherwise, serve challenge.
				recordAdvancedThreat(r, "pow_challenge_issued", 1.0, "PoW challenge issued due to low reputation", routeID, "bot", "LOW", "challenged")
				pc.serve(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// id builds the challenge identifier: unix seconds, a hash of the requesting
// client's identity, and a MAC over both under the route key.
//
// The MAC is what makes the ID the server's. Without it, verification
// recomputed the hash over whatever ID the client sent, so a bot could mint
// its own, solve it once offline and present it on every request -- and dated
// a year ahead, past any expiry check, forever. The secret the router insists
// on before installing the middleware was never read.
//
// The identity is the resolved client address plus User-Agent, the same pair
// the bot-management token binds to, and deliberately not the reputation ID:
// that is JA4+ when available, and JA4H is shaped by the request headers, so
// the page's fetch() that answers the challenge would carry a different one
// from the navigation that received it and every legitimate answer would be
// refused. The identity is hashed rather than interpolated because the ID
// reaches a response header, a JSON body and a nonce'd <script>; hex by
// construction is safe in all three. Truncating to 8 bytes keeps the ID short;
// it identifies a challenge, it is not a secret.
func (c powChallenge) id(ts int64, r *http.Request) string {
	fpSum := sha256.Sum256([]byte(telemetry.ClientIPOf(r) + "\x00" + r.UserAgent()))
	prefix := strconv.FormatInt(ts, 10) + "-" + hex.EncodeToString(fpSum[:8])
	mac := hmac.New(sha256.New, c.key)
	_, _ = io.WriteString(mac, prefix)
	return prefix + "-" + hex.EncodeToString(mac.Sum(nil))[:powMACLen]
}

// verify reports whether the request carries a solution to a challenge this
// route issued to this client within powChallengeTTL.
func (c powChallenge) verify(r *http.Request) bool {
	if len(c.key) == 0 {
		return false
	}
	id := r.Header.Get(PowHeaderID)
	parts := strings.Split(id, "-")
	if len(parts) != 3 {
		return false
	}
	ts, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	if age := time.Since(time.Unix(ts, 0)); age > powChallengeTTL || age < -powClockSkew {
		return false
	}
	// Recomputed for the presenting client under this route's key, so an ID
	// issued to another client, under another secret, or by the client itself
	// fails here before any hashing.
	if subtle.ConstantTimeCompare([]byte(c.id(ts, r)), []byte(id)) != 1 {
		return false
	}
	sum := sha256.Sum256([]byte(id + r.Header.Get(PowNonceHeader)))
	hashHex := hex.EncodeToString(sum[:])
	return strings.HasPrefix(hashHex, strings.Repeat("0", c.difficulty)) &&
		hashHex == r.Header.Get(PowHeaderSolution)
}

// issuedChallenge is one challenge handed to one client: the id it must
// answer, the salt and difficulty it is told, and the CSP nonce for the page
// that solves it. Grouped so the two writers take a receiver rather than four
// positional arguments of which three are strings.
type issuedChallenge struct {
	id         string
	salt       string
	difficulty int
	nonce      string
}

// powChallengePage is the browser fallback: a page whose script solves the
// challenge and retries with the answer in headers.
//
// #nosec G705 -- its three sinks (the CSP nonce attribute, a JS string literal
// and the body text) all receive constrained alphabets: nonce is standard
// base64, id is [0-9a-f-] by construction in powChallenge.id, and difficulty
// is an int. None can carry a quote or an angle bracket. See id for why the
// client fingerprint is hashed before it reaches any of them.
const powChallengePage = `<html>
<head><title>Security Check - Gateon</title></head>
<body style="font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f4f4f9;">
	<div style="background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; max-width: 400px;">
		<h2 style="color: #333;">Security Check</h2>
		<p style="color: #666;">Your connection exhibits unusual patterns. Please wait while we verify your browser...</p>
		<div id="loader" style="margin: 20px auto; border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%%; width: 30px; height: 30px; animation: spin 2s linear infinite;"></div>
		<script nonce="%s">
			async function solve() {
				const id = "%s";
				const difficulty = %d;
				const target = "0".repeat(difficulty);
				let nonce = 0;
				while (true) {
					const val = id + nonce;
					const msgUint8 = new TextEncoder().encode(val);
					const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
					const hashArray = Array.from(new Uint8Array(hashBuffer));
					const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
					if (hashHex.startsWith(target)) {
						fetch(window.location.href, {
							headers: {
								'X-Gateon-Pow-ID': id,
								'X-Gateon-Pow-Nonce': nonce.toString(),
								'X-Gateon-Pow-Solution': hashHex
							}
						}).then(res => {
							if (res.ok) window.location.reload();
						});
						break;
					}
					nonce++;
					if (nonce %% 1000 === 0) await new Promise(r => setTimeout(r, 0));
				}
			}
			solve();
		</script>
		<style>@keyframes spin { 0%% { transform: rotate(0deg); } 100%% { transform: rotate(360deg); } }</style>
	</div>
</body>
</html>`

// wantsJSON reports whether the caller is an XHR or fetch rather than a
// navigation, and so wants a machine-readable challenge.
func wantsJSON(r *http.Request) bool {
	return r.Header.Get("X-Requested-With") == "XMLHttpRequest" ||
		strings.Contains(r.Header.Get(kind.HeaderAccept), "application/json")
}

// writeJSON answers an XHR caller with the challenge as JSON.
func (ch issuedChallenge) writeJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	// #nosec G705 -- constrained alphabets only; see powChallengePage.
	fmt.Fprintf(w, `{"error":"proof_of_work_required","challenge_id":"%s","salt":"%s","difficulty":%d}`,
		ch.id, ch.salt, ch.difficulty)
}

// writePage answers a browser with the page that solves the challenge.
func (ch issuedChallenge) writePage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Content-Security-Policy",
		fmt.Sprintf("default-src 'self'; script-src 'self' 'nonce-%s'; style-src 'self' 'unsafe-inline';", ch.nonce))
	w.WriteHeader(http.StatusTooManyRequests)
	// #nosec G705 -- constrained alphabets only; see powChallengePage.
	fmt.Fprintf(w, powChallengePage, ch.nonce, ch.id, ch.difficulty)
}

// serve issues a challenge: headers plus a JSON body for XHR callers, or a
// page whose script solves it for browsers.
func (c powChallenge) serve(w http.ResponseWriter, r *http.Request) {
	ch := issuedChallenge{
		id:         c.id(time.Now().Unix(), r),
		salt:       strconv.FormatInt(time.Now().UnixNano(), 36),
		difficulty: c.difficulty,
		nonce:      GenerateNonce(),
	}

	w.Header().Set(PowHeaderID, ch.id)
	w.Header().Set(PowHeaderChallenge, ch.salt)
	w.Header().Set("X-Gateon-Pow-Difficulty", strconv.Itoa(ch.difficulty))

	if wantsJSON(r) {
		ch.writeJSON(w)
		return
	}
	ch.writePage(w)
}
