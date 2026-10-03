// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package challenge

import (
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/request"
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

// categoryBot is the threat category proof-of-work files under.
//
// A local constant rather than an addition to kind's vocabulary, which is a
// deliberate distinction. Severity and ActionTaken live in kind because
// consumers match on them exactly and a typo silently disappears a refusal.
// Category is not that: recordMitigationFunnel in internal/telemetry matches
// only "waf" and "abuse", and everything else is descriptive text the
// dashboard shows. Naming it here removes the repetition without inventing a
// shared vocabulary the consumers do not actually require.
const categoryBot = "bot"

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
	routeID    string
}

// Pow challenges a client whose threat score exceeds threshold to solve a
// proof of work before its request reaches the origin.
func Pow(difficulty int, threshold float64, secret string, routeID string) kind.Middleware {
	pc := powChallenge{key: powKey(secret), difficulty: difficulty, routeID: routeID}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Scoped to the client's network, not the browser class: a challenge
			// served because someone else's score is bad is a false positive that
			// costs every user of that browser a round trip.
			if pc.exempt(r) ||
				!threatExceeds(telemetry.GetReputationScore(telemetry.GetReputationID(r)), threshold) {
				next.ServeHTTP(w, r)
				return
			}
			pc.challengeOrPass(next, w, r)
		})
	}
}

// exempt skips gateon's own traffic, a difficulty of 0, and an allowlisted
// source. A proof-of-work challenge is an active mitigation: it costs the
// client a round trip and CPU, and an API client or monitoring probe the
// operator has vouched for cannot solve one at all.
//
// The first test used to be kind.IsInternalPath(r.URL.Path), which matches
// gateon's management paths by *prefix* -- /v1/routes, /v1/global,
// /v1/security and so on. On a proxy route those are not gateon's paths, they
// are the upstream's, so on a catch-all route a client disabled the challenge
// by prefixing their request path. RequestState.IsManagement is set by the
// entrypoint from which listener accepted the connection, which is not
// something a request can claim.
func (c powChallenge) exempt(r *http.Request) bool {
	rs := request.GetRequestState(r)
	return (rs != nil && rs.IsManagement) || c.difficulty <= 0 ||
		mitigation.IsAllowlisted(telemetry.ClientIPOf(r))
}

// challengeOrPass serves a client that must prove work: through with a
// current pass or a correct solution, otherwise a challenge.
func (c powChallenge) challengeOrPass(next http.Handler, w http.ResponseWriter, r *http.Request) {
	if c.hasPass(r) {
		next.ServeHTTP(w, r)
		return
	}
	if r.Header.Get(PowHeaderSolution) != "" && r.Header.Get(PowNonceHeader) != "" {
		if c.verify(r) {
			telemetry.MiddlewareBotManagementTotal.WithLabelValues(c.routeID, "pow_challenge_solved").Inc()
			c.setPass(w, r)
			next.ServeHTTP(w, r)
			return
		}
		kind.RecordThreat(r, kind.Threat{
			Type:        "pow_invalid_solution",
			Score:       10.0,
			Details:     "Invalid PoW solution provided",
			RouteID:     c.routeID,
			Category:    categoryBot,
			Severity:    kind.SeverityMedium,
			ActionTaken: kind.ActionChallenged,
		})
	}
	// Counted, not recorded as a threat. Serving a challenge is the gateway's
	// action, not evidence: the signal that lowered the score is already on
	// record. As a threat it was a second signal type for the correlator and
	// a "challenged" action for escalation, so one blocked attack and one
	// challenge made a critical incident that zeroed the score, and the
	// reputation blocker refused the client before it could solve anything
	// (ADR 0045).
	telemetry.MiddlewareBotManagementTotal.WithLabelValues(c.routeID, "pow_challenge_served").Inc()
	c.serve(w, r)
}

// threatExceeds reports whether a client whose reputation is reputation must
// solve a proof of work at threshold: when its threat score, 100 - reputation,
// exceeds the threshold. That is what the setting's label says, and the scale
// the tarpit beside it uses (ADR 0045).
//
// It used to challenge when the reputation itself was below the threshold. At
// the recommended 5 that meant a reputation under 5, which the reputation
// blocker refuses before this runs and which penalties of 50 step over, so
// proof-of-work challenged nobody. Strictly greater, so that a threshold left
// at 0 challenges every client with any penalty rather than every client.
func threatExceeds(reputation, threshold float64) bool {
	return 100-reputation > threshold
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
