// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"context"
	"net/http"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/security/reputation"
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

			if refusal := addressRefusal(r.Context(), rs, ip); refusal != refusedNone {
				refuseBlockedAddress(w, r, ip, refusal)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// refuseBlockedAddress answers 403 for an address AddressBlocked refuses, and
// records which list refused it.
func refuseBlockedAddress(w http.ResponseWriter, r *http.Request, ip string, refusal addressRefusalKind) {
	// The block refused this, not a credential check. Counted as a refused
	// attempt, a shunned address's own POSTs would renew its shun from the
	// shun's refusals once it lapsed (ADR 0031).
	request.MarkRefused(r, request.RefusalMitigation)
	threat := telemetry.SecurityThreat{
		Type:        "ip_mitigation",
		SourceIP:    ip,
		Category:    "threat_intel",
		Severity:    kind.SeverityHigh,
		ActionTaken: kind.ActionBlocked,
		Details:     "Request blocked due to mitigated IP (IP Shunning)",
		RequestURI:  r.URL.RequestURI(),
		Method:      r.Method,
		UserAgent:   r.UserAgent(),
	}
	body := "Forbidden: IP Shunned by Security Policy"
	if refusal == refusedByFeed {
		// Not on the mitigation list, so a feed listed it. The type stays
		// a mitigation type so the refusal is never evidence towards an
		// escalation (escalateMitigation), and the threat carries no score,
		// so it moves no reputation.
		threat.Details = "Request blocked: the address is listed by an IP reputation feed"
		body = "Forbidden: Address Listed by an IP Reputation Feed"
	}
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(body))
	telemetry.RecordSecurityThreat(telemetry.RecordSecurityThreatWithJA4(r, threat))
}

// AddressBlocked reports whether a client at ip is refused by the IP
// mitigation list: the address is on it, and it is not exempt from enforcement
// -- loopback and GATEON_MITIGATION_ALLOWLIST, the rule the fingerprint and
// reputation blocks apply (exemptFromEnforcement). IPMitigation asks it for
// every request and a TCP entrypoint for every connection it accepts, so what
// one refuses the other refuses (ADR 0032). IPMitigation used to refuse an
// allowlisted or loopback address on the list, which the allowlist -- "never
// mitigated" -- says it must not, and which ADR 0029 left open.
//
// A threat-feed listing (reputation.Listed) is refused here as well, so the
// feed switch -- "block known malicious actors" -- is enforced on every
// entrypoint and route by the decision that already refuses blocked
// addresses, under the same exemption. It used to be enforced only by a WAF
// rule behind a second switch, and refused no one without it (truth T3, ADR
// 0044).
func AddressBlocked(ip string) bool {
	return addressRefusal(context.Background(), nil, ip) != refusedNone
}

// addressRefusalKind is which list, if any, refuses an address.
type addressRefusalKind uint8

const (
	refusedNone addressRefusalKind = iota
	refusedByMitigation
	refusedByFeed
)

// addressRefusal is AddressBlocked, saying which list refused. rs is the state
// of the request the decision is for, whose lookup budget bounds the wait; nil
// for a connection being accepted, which waits one lookup deadline at most.
func addressRefusal(ctx context.Context, rs *request.RequestState, ip string) addressRefusalKind {
	if ip == "" {
		return refusedNone
	}
	refusal := listRefusal(ctx, rs, ip)
	if refusal != refusedNone && exemptFromEnforcement(ip) {
		return refusedNone
	}
	return refusal
}

// listRefusal is which list refuses ip, before its exemption -- except that
// the exemption is decided before the database is asked, never after. It
// costs a parse and no I/O; it used to be read only after the lookup, so
// loopback -- a health check, a local proxy, the same-host tunnel -- waited
// for the database like any other client and hung with it (dataplane DP-N1,
// ADR 0054). An address the cache answers for -- nearly every request -- pays
// for neither. The lookup itself waits at most the request's lookup budget,
// and decides one that cannot finish the way ADR 0043 decides a failed one.
// The feed is asked last and without a lock; with no feed loaded it costs an
// atomic load.
func listRefusal(ctx context.Context, rs *request.RequestState, ip string) addressRefusalKind {
	blocked, cached := telemetry.IPMitigationFromCache(ip)
	if !cached {
		if exemptFromEnforcement(ip) {
			return refusedNone
		}
		lookupCtx, cancel := lookupContext(ctx, rs)
		blocked = telemetry.IsIPMitigatedContext(lookupCtx, ip)
		cancel()
	}
	switch {
	case blocked:
		return refusedByMitigation
	case reputation.Listed(ip):
		return refusedByFeed
	}
	return refusedNone
}

// lookupContext is what a block lookup for the request rs belongs to waits
// under: ctx, ending at the request's lookup budget, which the first lookup
// that needs one sets one lookup deadline ahead
// (request.RequestState.BlockLookupsUntil). Both IPMitigation and
// UserMitigation run at the entrypoint and again at the route; with a
// database that does not answer, each lookup waiting its own deadline made a
// new client wait four. Reached only when the cache has no answer, so the
// context it allocates is off the path nearly every request takes. With no
// state -- a connection -- the lookup's own deadline is the bound.
func lookupContext(ctx context.Context, rs *request.RequestState) (context.Context, context.CancelFunc) {
	if rs == nil {
		return ctx, func() {}
	}
	if rs.BlockLookupsUntil == 0 {
		rs.BlockLookupsUntil = time.Now().Add(telemetry.BlockLookupTimeout()).UnixNano()
	}
	return context.WithDeadline(ctx, time.Unix(0, rs.BlockLookupsUntil))
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
//
// A block covers a network, so it reaches clients that did not earn it; the
// ones GATEON_MITIGATION_ALLOWLIST names, and loopback, are served as the
// reputation blocker serves them (exemptFromEnforcement, ADR 0029).
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
	// As listRefusal: the exemption is read only for a request a block would
	// refuse -- and before the database is asked, never after, so an exempt
	// client never waits for it (ADR 0054). The address is the one the key is
	// scoped with, cached on the state.
	blocked, cached := telemetry.UserMitigationFromCache(key)
	if !cached {
		if exemptFromEnforcement(telemetry.ClientIPOf(r)) {
			next.ServeHTTP(w, r)
			return
		}
		ctx, cancel := lookupContext(r.Context(), rs)
		blocked = telemetry.IsUserMitigatedContext(ctx, key)
		cancel()
	}
	if !blocked || exemptFromEnforcement(telemetry.ClientIPOf(r)) {
		next.ServeHTTP(w, r)
		return
	}

	request.MarkRefused(r, request.RefusalMitigation) // not a credential check (ADR 0031)
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
