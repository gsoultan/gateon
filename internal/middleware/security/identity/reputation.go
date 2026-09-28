// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/security/mitigation"
	"github.com/gsoultan/gateon/internal/telemetry"
)

type reputationHandler struct {
	next    http.Handler
	routeID string
}

func (h *reputationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// No CORS-preflight exemption; see kind.IsCorsPreflight.
	// Never block localhost or management traffic.
	//
	// This used to compare the *fingerprint* to "127.0.0.1", which was dead code
	// wherever it mattered: the fingerprint is JA4+ whenever one is available,
	// and JA4+ is always available because JA4H is derived from headers alone and
	// needs no TLS. The literal address only ever appeared here on the
	// fingerprint's own last-resort fallback, so loopback was in practice not
	// exempt at all. Comparing the resolved client address instead makes the
	// guard mean what it says.
	clientIP := telemetry.ClientIPOf(r)
	if exemptFromEnforcement(clientIP) {
		h.next.ServeHTTP(w, r)
		return
	}

	// The identity a refusal may act on is the browser class scoped to the
	// client's network, never the class alone. See repid.For:
	// JA4+ describes the software making the request, not the party making it,
	// so a 403 keyed on it refuses every user of that browser everywhere.
	repID := telemetry.GetReputationID(r)
	reputation := telemetry.GetReputationScore(repID)

	// Cache reputation in request state for downstream middlewares (like WAF)
	if rs := request.GetRequestState(r); rs != nil {
		rs.Reputation = reputation
	}

	if reputation < 2.0 && (os.Getenv("GATEON_TEST") == "" || os.Getenv("GATEON_ENABLE_TEST_REPUTATION") != "") {
		// Avoid blocking management traffic.
		isMgmt := false
		if rs := request.GetRequestState(r); rs != nil {
			isMgmt = rs.IsManagement
		}

		if !isMgmt {
			telemetry.RequestFailuresTotal.WithLabelValues(h.routeID, "l7_shun").Inc()
			logger.L.LogInfo("Reputation block triggered",
				"route", h.routeID,
				"request_id", kind.GetRequestID(r),
				"reputation", reputation,
				"reputation_id", repID)

			telemetry.RecordSecurityThreat(telemetry.RecordSecurityThreatWithJA4(r, telemetry.SecurityThreat{
				ID:          fmt.Sprintf("rep-block-%s-%s", h.routeID, repID),
				Type:        "reputation_block",
				SourceIP:    clientIP,
				Score:       100 - reputation,
				Details:     fmt.Sprintf("Blocked due to low reputation: %.2f (identity: %s)", reputation, repID),
				Time:        time.Now(),
				RouteID:     h.routeID,
				RequestURI:  r.URL.Path,
				Category:    "bot",
				Severity:    kind.SeverityHigh,
				ActionTaken: kind.ActionBlocked,
			}))

			// No credential was checked, so this is not an attempt (ADR 0031).
			request.MarkRefused(r, request.RefusalMitigation)
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Forbidden by Security Policy (Reputation Block)"))
			return
		}
	}

	h.next.ServeHTTP(w, r)
}

// exemptFromEnforcement reports whether a client is never refused by the
// identity blocks -- reputation, the fingerprint block and the IP block
// (AddressBlocked) alike, one rule for all three, on HTTP and TCP entrypoints:
// loopback, which is the gateway's own management traffic and, behind a local
// proxy that sets no forwarding header, every client; and
// GATEON_MITIGATION_ALLOWLIST.
//
// It exempts enforcement, never observation: the threat is still recorded
// downstream and still feeds correlation. An operator who allowlists their own
// pentest team wants to see what it found.
func exemptFromEnforcement(clientIP string) bool {
	// One rule for the whole gateway: the request path, the automatic shun and
	// the kernel shun map all decide exemption here (ADR 0035), so the three can
	// never drift. It stays off the pass-through path -- read only for a request
	// a block would otherwise refuse -- so the delegation costs nothing there.
	return mitigation.ExemptFromEnforcement(clientIP)
}

// ExemptFromEnforcement is exemptFromEnforcement for callers outside this
// package -- the TCP entrypoints, which apply the same exemption to their
// per-address connection cap and to closing an address's open L4 sessions when
// it is blocked (ADR 0036), so that loopback and GATEON_MITIGATION_ALLOWLIST
// mean one thing on every path. It exists so those callers do not re-derive the
// rule and drift from it.
func ExemptFromEnforcement(clientIP string) bool {
	return exemptFromEnforcement(clientIP)
}

// ReputationBlocker returns a middleware that blocks clients with extremely low reputation.
func ReputationBlocker(routeID string) kind.Middleware {
	return func(next http.Handler) http.Handler {
		return &reputationHandler{
			next:    next,
			routeID: routeID,
		}
	}
}
