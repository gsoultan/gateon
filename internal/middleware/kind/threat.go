// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package kind

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// Threat is one refusal or detection, as the dashboard and the SIEM will read
// it.
//
// A struct rather than the eight positional parameters this used to take.
// Five of those were strings -- routeID, category, severity, actionTaken and
// details -- sitting next to each other, so swapping two of them compiled
// cleanly and produced a threat filed under the wrong heading with nothing to
// notice. Severity and category in particular are a pair a reader cannot tell
// apart at a call site.
type Threat struct {
	Type        string
	Details     string
	RouteID     string
	Category    string
	Severity    string // one of the Severity* constants
	ActionTaken string // one of the Action* constants
	Score       float64
}

// RecordThreat files a threat for the dashboard, the alerting pipeline and the
// audit log.
//
// Loopback is skipped because the gateway talks to itself: health checks,
// readiness probes and the dashboard's own calls would otherwise fill the
// security view with the operator's own traffic and bury the real thing.
//
// Lives here rather than in a middleware package because every group records
// threats and none of them owns the shape. It is the fourth thing to move into
// kind for that reason, after the config parsers, the header constants and the
// severity vocabulary.
func RecordThreat(r *http.Request, t Threat) {
	if httputil.IsLoopback(request.ClientAddr(r)) {
		return
	}

	logger.SecurityEvent(t.Type, r, t.Details)
	telemetry.RecordSecurityThreat(telemetry.RecordSecurityThreatWithJA4(r, telemetry.SecurityThreat{
		ID:          fmt.Sprintf("adv-%s-%d", t.Type, time.Now().UnixNano()),
		Type:        t.Type,
		SourceIP:    request.ClientAddr(r),
		Score:       t.Score,
		Details:     t.Details,
		Time:        time.Now(),
		RouteID:     t.RouteID,
		RequestURI:  r.RequestURI,
		Category:    t.Category,
		Severity:    t.Severity,
		ActionTaken: t.ActionTaken,
		Method:      r.Method,
		UserAgent:   r.UserAgent(),
	}))
}
