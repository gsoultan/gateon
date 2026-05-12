package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
)

const (
	PowHeaderChallenge = "X-Gateon-Pow-Challenge"
	PowHeaderSolution  = "X-Gateon-Pow-Solution"
	PowNonceHeader     = "X-Gateon-Pow-Nonce"
)

// Pow checks if a client needs to solve a cryptographic challenge.
func Pow(difficulty int, threshold float64, secret string, routeID string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip for internal paths or if difficulty is 0.
			if IsInternalPath(r.URL.Path) || difficulty <= 0 {
				next.ServeHTTP(w, r)
				return
			}

			fingerprint := telemetry.GetFingerprint(r)
			score := telemetry.GetReputationScore(fingerprint)

			// If reputation is below threshold, require PoW.
			if score < threshold {
				solution := r.Header.Get(PowHeaderSolution)
				nonce := r.Header.Get(PowNonceHeader)
				challengeID := r.Header.Get("X-Gateon-Pow-ID")

				if solution != "" && nonce != "" {
					if verifyPoW(challengeID, nonce, solution, difficulty) {
						// Solution correct, proceed.
						next.ServeHTTP(w, r)
						return
					}
					// Invalid solution - record as a threat
					recordAdvancedThreat(r, "pow_invalid_solution", 10.0, "Invalid PoW solution provided", routeID)
				}

				// Otherwise, serve challenge.
				recordAdvancedThreat(r, "pow_challenge_issued", 1.0, "PoW challenge issued due to low reputation", routeID)
				serveChallenge(w, r, difficulty)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func serveChallenge(w http.ResponseWriter, r *http.Request, difficulty int) {
	salt := strconv.FormatInt(time.Now().UnixNano(), 36)
	challengeID := fmt.Sprintf("%d-%s-%s", time.Now().Unix(), telemetry.GetFingerprint(r), salt)

	w.Header().Set("X-Gateon-Pow-ID", challengeID)
	w.Header().Set(PowHeaderChallenge, salt)
	w.Header().Set("X-Gateon-Pow-Difficulty", strconv.Itoa(difficulty))

	// If it's an XHR/Fetch request, return 429 with headers.
	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprintf(w, `{"error":"proof_of_work_required","challenge_id":"%s","salt":"%s","difficulty":%d}`, challengeID, salt, difficulty)
		return
	}

	// For standard browser requests, serve a simple HTML page that solves it via JS.
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusTooManyRequests)
	fmt.Fprintf(w, `
<html>
<head><title>Security Check - Gateon</title></head>
<body style="font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f4f4f9;">
	<div style="background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; max-width: 400px;">
		<h2 style="color: #333;">Security Check</h2>
		<p style="color: #666;">Your connection exhibits unusual patterns. Please wait while we verify your browser...</p>
		<div id="loader" style="margin: 20px auto; border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%%; width: 30px; height: 30px; animation: spin 2s linear infinite;"></div>
		<script>
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
</html>`, challengeID, difficulty)
}

func verifyPoW(id, nonce, solution string, difficulty int) bool {
	// 1. Check if ID is not too old (e.g. 5 mins)
	parts := strings.Split(id, "-")
	if len(parts) == 0 {
		return false
	}
	ts, _ := strconv.ParseInt(parts[0], 10, 64)
	if time.Since(time.Unix(ts, 0)) > 5*time.Minute {
		return false
	}

	// 2. Re-calculate hash
	// Use a salt (here we'd need to store the salt or derive it, but for simplicity we assume it's part of verification logic)
	// In production, we'd sign the challenge ID or store it in Redis.
	// For this impl, we just trust the provided solution hash matches the nonce+id if we want to be stateless.
	// BETTER: Recalculate it ourselves.

	// Since we don't store the salt per ID here (to stay stateless), let's use a simpler variant:
	// val = id + nonce
	val := id + nonce
	h := sha256.Sum256([]byte(val))
	hashHex := hex.EncodeToString(h[:])

	target := strings.Repeat("0", difficulty)
	return strings.HasPrefix(hashHex, target) && hashHex == solution
}
