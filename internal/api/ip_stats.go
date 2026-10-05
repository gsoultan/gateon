// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// IPStats holds aggregated metrics for a specific source IP.
type IPStats struct {
	TotalRequests int
	Error4xx      int
	Error401      int
	Error403      int
	Error404      int
	Error5xx      int
	TotalDuration float64
	LastSeen      time.Time
	UniquePaths   map[string]struct{}
	CountryCode   string
	UserAgents    map[string]struct{}
	Methods       map[string]int
	Referers      map[string]int
	BurstCount    int            // Requests in the peak 10-second window
	JA4s          map[string]int // Track JA4 fingerprints per IP
	WAFHits       int            // Count of requests blocked by WAF rules
	WAFWarnings   int            // Count of requests flagged but not blocked by WAF rules
	WAFRules      map[string]int // Track specific WAF rules triggered
	LastTrace     *telemetry.TraceRecord

	// Harm evidence: what an address must show before a detector whose finding
	// can end in a kernel throttle may act on it. See harmEvidence.
	FailedPaths      map[string]int // failed (4xx/5xx) requests per path; nil until the first failure
	Posts            int            // POST requests
	PostAuthFailures int            // POSTs answered 401 or 403
	AttackEvidence   float64        // request-path attack decisions in the evidence window; see attackEvidenceWeight

	// Brute-force evidence: credential attempts (credentialAttempt) answered
	// 401 or 403, in all and per path. The per-path map is nil until the first.
	CredentialFailures     int
	CredentialFailurePaths map[string]int

	// Advanced Behavioral Signals
	IATSum        float64   // Sum of durations between requests (ms)
	IATSumSq      float64   // Sum of squares of durations (ms^2)
	IATCount      int       // Number of inter-arrival intervals
	LastRequestAt time.Time // Time of previous request for IAT calculation
	LastPathHash  uint64    // Previous path hash
	PrevPathHash  uint64    // Path hash before LastPathHash
}

// credentialAttempt reports whether a traced request could have been someone
// trying a credential: a POST, which is how a login form and a token request
// submit one, or any request whose Authorization header carried a password,
// which is how HTTP Basic and Digest do.
//
// A refused GET is otherwise not an attempt. A tab whose session expired keeps
// polling, and every poll is a GET answered 401 that presents the one session
// it had; so does an application re-presenting a bearer token the server issued
// and has since expired. Headers are not in the summary traces the analysis
// reads, so the recording path decides the password case once, from the
// scheme alone, and stores the answer (telemetry.TraceRecord.PasswordAuth).
//
// What this does not see: credentials guessed through a GET query string, and a
// token-guessing client presenting a different bearer token each time. Neither
// is how credential guessing is done against a login form or Basic auth, and
// counting every refused GET to catch them is what reported the expired tab.
//
// Nor is a request the gateway itself refused for the token it presented
// (TraceRecord.Refusal, from the mark the refusing middleware wrote): a
// Connect, gRPC-Web or GraphQL poller re-presenting an expired session over
// POST -- the dashboard's own calls among them -- is a session that ended, not
// a guess (ADR 0031). A POST a backend refused is still counted: the gateway
// did not check its credential and cannot say what it was. So is one the
// gateway's authentication refused, which it marks as such (ADR 0059).
func credentialAttempt(tr *telemetry.TraceRecord) bool {
	return (tr.Refusal == "" || tr.Refusal == authenticationRefusal) &&
		(tr.Method == http.MethodPost || tr.PasswordAuth)
}

// authenticationRefusal is how a trace records a refusal by the gateway's
// authentication (request.RefusalAuthentication).
var authenticationRefusal = request.RefusalAuthentication.String()

// Failures is how many of the address's traced requests failed (4xx or 5xx).
func (s *IPStats) Failures() int {
	return s.Error401 + s.Error403 + s.Error404 + s.Error4xx + s.Error5xx
}

// estimatedRequests is how many requests the address really sent, given that
// the trace store keeps every failure but only one success in sampleRate
// (GATEON_TRACE_SAMPLE_RATE). Every ratio a detector judges an address by is
// taken over this, not over the traces: read off a 1-in-20 sample, an office's
// egress with a 4% failure rate shows about 45% failures, and one with a few
// broken links looks like a scanner.
func (s *IPStats) estimatedRequests(sampleRate uint32) float64 {
	failures := s.Failures()
	successes := s.TotalRequests - failures
	return float64(failures) + float64(successes)*float64(max(sampleRate, 1))
}

// Harm-evidence bars. Each shape requires a count, so a handful of requests
// cannot qualify, and a share of the address's own traffic: a throttle limits
// the whole address, and one address can carry an office, a CGNAT pool or a
// VPN exit, so the harmful traffic has to be most of what it sends, not one
// user's worth of it. The escalation to an IP shun makes the same trade
// (ipShunMinClasses in the telemetry store, ADR 0029).
const (
	harmMinFailures     = 10  // failed requests before an address can look like a scan
	harmMinFailedPaths  = 10  // distinct paths those failures were spread over
	harmMinFailureShare = 0.5 // of all its requests
	harmMinAuthFailures = 10  // POSTs answered 401/403 before it can look like credential guessing
	harmMinAuthShare    = 0.3 // of all its requests
	harmMinAttackWeight = 3.0 // three WAF blocks, or one decisive decision (attackEvidenceWeight)
	harmMinAttackShare  = 0.2 // of all its requests
)

// harmEvidence reports whether the address's traffic is harmful, as opposed to
// merely unusual, and names the shape.
//
// Unusual is not harmful. A dashboard polling every five seconds, a CI runner
// walking an API, a monitoring probe and an office's egress are all outliers
// among browsers, and an isolation forest rightly isolates each of them; none
// of them is an attack. So every detector that can lead to a throttle -- the
// Neural Sentinel, and the timing check that could push a client over the
// threat threshold -- also asks for one of three shapes of attack:
//
//   - a scan: many requests failing, across many paths;
//   - credential guessing: many POSTs answered 401/403. POSTs, because a tab
//     whose session expired keeps polling with GETs that now answer 401, and
//     is guessing nothing;
//   - attacks the request path itself caught: WAF blocks, traps, malware
//     uploads, brute-force or exploit-scan detections (attackEvidenceWeight).
func (s *IPStats) harmEvidence(sampleRate uint32) (string, bool) {
	requests := s.estimatedRequests(sampleRate)
	if requests <= 0 {
		return "", false
	}
	failures := s.Failures()
	if failures >= harmMinFailures && len(s.FailedPaths) >= harmMinFailedPaths &&
		float64(failures)/requests >= harmMinFailureShare {
		return fmt.Sprintf("%d failed requests across %d paths", failures, len(s.FailedPaths)), true
	}
	if s.PostAuthFailures >= harmMinAuthFailures && float64(s.PostAuthFailures)/requests >= harmMinAuthShare &&
		2*s.PostAuthFailures >= s.Posts {
		return fmt.Sprintf("%d of %d POSTs refused with 401/403", s.PostAuthFailures, s.Posts), true
	}
	if s.AttackEvidence >= harmMinAttackWeight && s.AttackEvidence/requests >= harmMinAttackShare {
		return fmt.Sprintf("attacks caught by the request path (weight %.0f)", s.AttackEvidence), true
	}
	return "", false
}
