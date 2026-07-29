package middleware

import (
	"net/http"
	"os"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

type reputationHandler struct {
	next    http.Handler
	routeID string
}

func (h *reputationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fpID := telemetry.GetFingerprintHash(r)
	if rs := request.GetRequestState(r); rs != nil && rs.JA4 != "" {
		fpID = rs.JA4
	}

	reputation := telemetry.GetReputationScore(fpID)

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
				"fingerprint", fpID)

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
