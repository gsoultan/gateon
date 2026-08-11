// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/security/entropy"
	secwaf "github.com/gsoultan/gateon/internal/security/waf"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/types"
)

// Threat severity levels, as stored on a SecurityThreat and rendered by the
// dashboard. A closed vocabulary: the dashboard filters and the SIEM mapping
// both switch on these exact strings, so a typo in one of them is a threat that
// silently stops matching rather than a compile error.
const (
	severityCritical = "critical"
	severityHigh     = "high"
	severityMedium   = "medium"
	severityLow      = "low"
)

// Threat recording used to live in Coraza's ProcessLogging hook, where it read
// the anomaly score out of a transaction variable collection through an
// unchecked type assertion and looked up human-readable text in a map keyed by
// CRS rule number.
//
// Both of those are gone. gwaf reports a decision as data — rule, message,
// severity, confidence, matched span and the decoding that revealed it — so the
// record is built from what the engine actually decided rather than from a
// lookup table that had to be kept in step with somebody else's ruleset.

const (
	// categoryGeneral is the fallback for a rule gateon does not own — one from
	// gwaf's core ruleset, which carries no gateon category.
	categoryGeneral = "general"

	actionBlocked  = "blocked"
	actionDetected = "detected"

	// defaultThreatConfidence is used when confidence scoring is off. It is a
	// deliberate middle value: reporting certainty gateon has not computed
	// would be worse than reporting an average.
	defaultThreatConfidence = 0.8
)

// wafObservation is everything gateon records about one WAF decision. It is
// assembled on the request goroutine and must not outlive the transaction: the
// matches a transaction returns are owned by it and invalidated on Close.
type wafObservation struct {
	decision gwaf.Decision
	matches  []gwaf.Match
	request  *http.Request
	routeID  string
	cfg      WAFConfig
	repScore float64
}

// recordWAFDecision turns a decision into telemetry, metrics and a threat
// record for the dashboard.
func recordWAFDecision(o wafObservation) {
	blocked := o.decision.Blocked()
	if !blocked && len(o.matches) == 0 {
		// Nothing matched and nothing was refused: there is no event here, and
		// recording one per request is how a telemetry store fills up with
		// entries nobody can act on.
		return
	}

	if blocked {
		logger.L.LogInfo("WAF blocked a request",
			"rule", o.decision.RuleID(),
			"reason", o.decision.Reason(),
			"score", o.decision.Score(),
			"route", o.routeID)
		telemetry.RequestFailuresTotal.
			WithLabelValues(o.routeID, "waf:"+o.decision.RuleID().String()).Inc()
	}

	clientIP := request.GetClientIP(o.request, o.cfg.TrustCloudflare)
	if blocked && clientIP != "" {
		telemetry.GetAggregator().RecordWAFBlock(clientIP)
		o.applyAdaptiveMitigation(clientIP)
	}

	telemetry.RecordSecurityThreat(telemetry.RecordSecurityThreatWithJA4(o.request, o.threat(clientIP)))
}

// threat builds the dashboard record for a decision.
func (o wafObservation) threat(clientIP string) telemetry.SecurityThreat {
	blocked := o.decision.Blocked()
	explanation, recommendation, triggered := explainWAFDecision(o.decision, o.matches)
	severity, category := wafSeverityAndCategory(o.matches, o.decision)

	action := actionDetected
	if blocked {
		action = actionBlocked
	}

	confidence := defaultThreatConfidence
	if o.cfg.EnableConfidenceScoring {
		confidence = calculateConfidence(o.repScore, severity, o.decision.Score(), false)
	}

	// Two properties this key has to have, and the old form
	// "waf-<action>-<route>-<nanos>" had neither.
	//
	// Bounded: the route is named by a human, and the dev gateway alone ships
	// one 46 characters long. Interpolating it gave the primary key a length
	// nobody controls. The route is not lost — route_id is its own column below.
	//
	// Unique: a timestamp is not an identity. time.Now() resolves to about a
	// microsecond, so two threats recorded in the same tick produced the same
	// key and the second lost a primary-key race — during an attack burst,
	// which is precisely when the Security Hub has to be complete.
	id := "waf-" + action + "-" + uuid.NewString()
	telemetry.RegisterRecommendation(id, recommendation)

	var ja4, ja4h, fingerprint string
	if rs := request.GetRequestState(o.request); rs != nil {
		ja4, ja4h, fingerprint = rs.JA4, rs.JA4H, rs.JA4Plus
	}

	return telemetry.SecurityThreat{
		ID:             id,
		Type:           "waf_" + action,
		SourceIP:       clientIP,
		Fingerprint:    fingerprint,
		Score:          100,
		Details:        explanation,
		Recommendation: recommendation,
		Time:           time.Now(),
		RouteID:        o.routeID,
		RequestURI:     o.request.RequestURI,
		Category:       category,
		Severity:       severity,
		ActionTaken:    action,
		Mitigated:      blocked,
		JA4:            ja4,
		JA4H:           ja4h,
		UserAgent:      o.request.Header.Get("User-Agent"),
		Method:         o.request.Method,
		Confidence:     confidence,
		Entropy:        matchedEntropy(o.matches),
		TriggeredRules: triggered,
	}
}

// applyAdaptiveMitigation rate-limits a source that keeps scoring highly.
//
// It deliberately does not shun at L3: a shunned address blocks every user
// behind the same NAT or CGNAT egress, and the JA4-based mitigation is precise
// where an address is not.
func (o wafObservation) applyAdaptiveMitigation(clientIP string) {
	if o.cfg.EbpfManager == nil || o.decision.Score() < 10 {
		return
	}
	if clientIP == "127.0.0.1" || clientIP == "::1" || clientIP == "localhost" {
		return
	}
	_ = o.cfg.EbpfManager.SetAdaptiveRateLimit(clientIP, time.Second)
}

// wafSeverityAndCategory derives the dashboard's two summary fields.
//
// The category used to be read off a CRS tag or inferred from the rule's
// numeric range. Now it is the rule's own first non-attack tag, falling back to
// the attack tag, which is the same information without the range arithmetic.
func wafSeverityAndCategory(matches []gwaf.Match, d gwaf.Decision) (severity, category string) {
	category = categoryGeneral

	worst := types.SeverityNotice
	for _, m := range matches {
		if m.Severity >= worst {
			worst = m.Severity
		}
		if category == categoryGeneral {
			if c := categoryFromTags(m.RuleID); c != "" {
				category = c
			}
		}
	}
	if d.Blocked() && d.Severity() >= worst {
		worst = d.Severity()
	}
	if category == categoryGeneral {
		if c := categoryFromTags(d.RuleID()); c != "" {
			category = c
		}
	}
	return worst.String(), category
}

// categoryFromTags looks the rule up in gateon's corpus.
//
// A rule from gwaf's own ruleset is not in it, which is why the fallback is a
// generic category rather than a wrong one.
func categoryFromTags(id types.RuleID) string {
	if info, ok := secwaf.LookupRule(uint32(id)); ok {
		return info.Category
	}
	return ""
}

// matchedEntropy is the highest Shannon entropy across matched spans, which the
// dashboard uses to distinguish an obfuscated payload from a plain one.
func matchedEntropy(matches []gwaf.Match) float64 {
	var highest float64
	for _, m := range matches {
		if m.Span.Len == 0 {
			continue
		}
		if e := entropy.CalculateString(m.Msg); e > highest {
			highest = e
		}
	}
	return highest
}

// explainWAFDecision produces the operator-facing text for a decision.
func explainWAFDecision(d gwaf.Decision, matches []gwaf.Match) (explanation, recommendation, triggered string) {
	ids := make([]uint32, 0, len(matches)+1)
	var b strings.Builder

	if d.Blocked() {
		b.WriteString(d.Message())
		if in := d.Interpretation(); in != "" && in != "none" {
			// The decoding that revealed the payload is the single most useful
			// fact when triaging: it distinguishes a plain attack from one
			// hidden behind an encoding the origin would have undone.
			b.WriteString(" (revealed by ")
			b.WriteString(in)
			b.WriteString(" decoding)")
		}
		if k := d.Key(); k != "" {
			b.WriteString(" in ")
			b.WriteString(d.Target().String())
			b.WriteString(":")
			b.WriteString(k)
		}
		ids = append(ids, uint32(d.RuleID()))
	}

	for _, m := range matches {
		id := uint32(m.RuleID)
		if len(ids) > 0 && ids[0] == id {
			continue
		}
		ids = append(ids, id)
		if b.Len() > 0 {
			b.WriteString("; ")
		}
		b.WriteString(m.Msg)
	}

	if b.Len() == 0 {
		b.WriteString("WAF matched a request")
	}
	if !d.Blocked() {
		b.WriteString(" (score ")
		b.WriteString(strconv.Itoa(d.Score()))
		b.WriteString(", below the blocking threshold)")
	}

	// The triggered-rule list is JSON rather than a comma-separated string
	// because the false-positive workflow and the dashboard both parse it as an
	// array. Emitting a different shape here would not fail anywhere; the
	// "exclude this rule" button would simply stop finding a rule to exclude.
	encoded, err := json.Marshal(ids)
	if err != nil {
		return b.String(), wafRecommendation(d, matches), "[]"
	}
	return b.String(), wafRecommendation(d, matches), string(encoded)
}

// wafRecommendation says what to do about the decision.
//
// It is derived from the decision's reason rather than from a per-rule table:
// the reason distinguishes the cases an operator actually treats differently —
// a rule fired, a score accumulated, or the engine could not finish — where a
// per-rule table mostly restated the rule's own message.
func wafRecommendation(d gwaf.Decision, matches []gwaf.Match) string {
	if !d.Blocked() {
		return "Observed but not blocked. Review whether these matches are legitimate traffic before raising the paranoia level."
	}
	switch {
	case d.Confidence() >= types.Certain:
		return fmt.Sprintf("Rule %s has no known false positives. If this was legitimate traffic, add a narrowly scoped exception for the exact path and field rather than disabling the rule.", d.RuleID())
	case len(matches) > 1:
		return fmt.Sprintf("Blocked on an accumulated score of %d across %d matches. Review each rule before excepting any one of them; the individual matches may be benign while the combination is not.", d.Score(), len(matches))
	default:
		return fmt.Sprintf("Rule %s (%s confidence) fired. If this is a false positive, scope an exception to the path and field shown rather than turning off the category.", d.RuleID(), d.Confidence())
	}
}
