// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

type reputationHandler struct {
	next    http.Handler
	routeID string
}

func (h *reputationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if IsCorsPreflight(r) {
		h.next.ServeHTTP(w, r)
		return
	}
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
	if httputil.IsLoopback(clientIP) {
		h.next.ServeHTTP(w, r)
		return
	}

	// The identity a refusal may act on is the browser class scoped to the
	// client's network, never the class alone. See telemetry.ReputationIDFor:
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
				"request_id", GetRequestID(r),
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
				Severity:    "HIGH",
				ActionTaken: actionBlocked,
			}))

			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Forbidden by Security Policy (Reputation Block)"))
			return
		}
	}

	h.next.ServeHTTP(w, r)
}

// ReputationBlocker returns a middleware that blocks clients with extremely low reputation.
func ReputationBlocker(routeID string) Middleware {
	return func(next http.Handler) http.Handler {
		return &reputationHandler{
			next:    next,
			routeID: routeID,
		}
	}
}
