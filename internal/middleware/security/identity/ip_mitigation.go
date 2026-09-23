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

// UserMitigation returns a middleware that blocks requests from mitigated JA4+ fingerprints.
// unmitigatedPaths are fetched by browsers and crawlers without a user ever
// asking, so a mitigated fingerprint refusing them produces phantom requests
// that break security isolation in e2e tests and confuse production triage.
var unmitigatedPaths = map[string]bool{
	"/favicon.ico": true,
	"/robots.txt":  true,
	"/sitemap.xml": true,
}

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
	var ja4plus string
	if rs != nil {
		ja4plus = rs.JA4Plus
	}
	if ja4plus == "" || !telemetry.IsUserMitigated(ja4plus) {
		next.ServeHTTP(w, r)
		return
	}

	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte("Forbidden: Compromised Fingerprint"))

	// Use resolved client IP from RequestState if available.
	clientIP := request.GetClientIP(r, config.EffectiveTrustCloudflare())
	if rs != nil && rs.ClientRemoteAddr != "" {
		clientIP = rs.ClientRemoteAddr
	}

	// Record threat for visibility in dashboard
	telemetry.RecordSecurityThreat(telemetry.RecordSecurityThreatWithJA4(r, telemetry.SecurityThreat{
		Type:        "user_mitigation",
		SourceIP:    clientIP,
		Category:    "threat_intel",
		Severity:    kind.SeverityHigh,
		ActionTaken: kind.ActionBlocked,
		Details:     "Request blocked due to mitigated user fingerprint (JA4+)",
		Fingerprint: ja4plus,
		RequestURI:  r.URL.RequestURI(),
		Method:      r.Method,
		UserAgent:   r.UserAgent(),
	}))
}
