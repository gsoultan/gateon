// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"net/http"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// IPMitigation moved out of standard.go with the security stage: it is the
// middleware that enforces an IP mitigation, and it sits on the same state as
// the reputation blocker beside it.

// IPMitigation returns a middleware that blocks requests from mitigated IPs.
func IPMitigation() kind.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// No CORS-preflight exemption; see kind.IsCorsPreflight. A shunned
			// IP is shunned whatever it says it is about to do.
			rs := request.GetRequestState(r)
			trustCloudflare := config.EffectiveTrustCloudflare()
			ip := request.GetClientIP(r, trustCloudflare)
			if rs != nil && rs.ClientRemoteAddr != "" {
				ip = rs.ClientRemoteAddr
			}

			if ip != "" && telemetry.IsIPMitigated(ip) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte("Forbidden: IP Shunned by Security Policy"))

				// Record threat for visibility in dashboard
				telemetry.RecordSecurityThreat(telemetry.RecordSecurityThreatWithJA4(r, telemetry.SecurityThreat{
					Type:        "ip_mitigation",
					SourceIP:    ip,
					Category:    "threat_intel",
					Severity:    kind.SeverityHigh,
					ActionTaken: kind.ActionBlocked,
					Details:     "Request blocked due to mitigated IP (IP Shunning)",
					RequestURI:  r.URL.RequestURI(),
					Method:      r.Method,
					UserAgent:   r.UserAgent(),
				}))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// unmitigatedPaths are fetched by browsers and crawlers without a user ever
// asking, so a mitigated fingerprint refusing them produces phantom requests
// that break security isolation in e2e tests and confuse production triage.
var unmitigatedPaths = map[string]bool{
	"/favicon.ico": true,
	"/robots.txt":  true,
	"/sitemap.xml": true,
}

// UserMitigation returns a middleware that refuses clients whose fingerprint is
// blocked on their network.
//
// The block is kept for, and read under, telemetry.GetReputationID -- the
// fingerprint's class on the client's /24 or /64 (repid.For) -- which is the
// key the recording path writes, and the one the reputation blocker behind
// this reads (ADR 0026). Keyed on the whole JA4+ it refused every user of one
// browser build on every network, while the client it was meant for shed it by
// dropping a Referer.
func UserMitigation() kind.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serveUserMitigation(next, w, r)
		})
	}
}

func serveUserMitigation(next http.Handler, w http.ResponseWriter, r *http.Request) {
	// No CORS-preflight exemption; see kind.IsCorsPreflight. unmitigatedPaths
	// stays, because those are paths the gateway chooses to answer, not a shape
	// the caller names to exempt itself.
	if unmitigatedPaths[r.URL.Path] {
		next.ServeHTTP(w, r)
		return
	}

	rs := request.GetRequestState(r)
	if rs == nil || rs.JA4Plus == "" {
		next.ServeHTTP(w, r)
		return
	}
	key := telemetry.GetReputationID(r)
	if !telemetry.IsUserMitigated(key) {
		next.ServeHTTP(w, r)
		return
	}

	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte("Forbidden: Compromised Fingerprint"))

	// Record threat for visibility in dashboard
	telemetry.RecordSecurityThreat(telemetry.RecordSecurityThreatWithJA4(r, telemetry.SecurityThreat{
		Type:        "user_mitigation",
		SourceIP:    telemetry.ClientIPOf(r),
		Category:    "threat_intel",
		Severity:    kind.SeverityHigh,
		ActionTaken: kind.ActionBlocked,
		Details:     "Request blocked: this client build is blocked on this network (" + key + ")",
		Fingerprint: rs.JA4Plus,
		RequestURI:  r.URL.RequestURI(),
		Method:      r.Method,
		UserAgent:   r.UserAgent(),
	}))
}
