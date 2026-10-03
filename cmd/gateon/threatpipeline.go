// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/security/correlation"
	"github.com/gsoultan/gateon/internal/security/mitigation"
	"github.com/gsoultan/gateon/internal/security/siem"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// Mitigation tuning environment variables.
const (
	envMitigationEnabled   = "GATEON_MITIGATION_ENABLED"   // default true
	envMitigationAutoShun  = "GATEON_MITIGATION_AUTO_SHUN" // default false (hard block)
	envMitigationAllowlist = "GATEON_MITIGATION_ALLOWLIST" // CIDR/IP list never mitigated
)

// signalQueueSize bounds the buffer between the threat broadcaster and the
// correlation engine; overflow signals are dropped (non-blocking).
const signalQueueSize = 1024

// envShipRawThreats, when true, also forwards every individual threat to the
// SIEM sink (in addition to correlated incidents).
const envShipRawThreats = "GATEON_SIEM_RAW_THREATS"

// startThreatPipeline wires Gateon's recorded security threats into the
// correlation engine and (optionally) a SIEM exporter. The correlation engine
// always runs and logs incidents; SIEM export is enabled only when configured
// via GATEON_SIEM_* environment variables. All goroutines exit when ctx is
// cancelled.
func startThreatPipeline(ctx context.Context, version string) {
	// First, and whatever the tier decides about correlation below: the
	// allowlist governs the request path's enforcement, not only the responder.
	publishMitigationAllowlist()

	shipper := initSIEMShipper(ctx, version)
	shipRaw := shipper != nil && boolEnvTrue(envShipRawThreats)

	// The correlation engine is the largest bounded RAM consumer (up to
	// MaxSources x MaxSignalsPerSource retained signals), so its bounds — and
	// whether it runs at all — follow the active resource profile. The minimal
	// profile turns it off; SIEM raw export (if configured) still works.
	td := config.CurrentTierDefaults()
	correlate := td.CorrelationEnabled

	var signals chan correlation.Signal
	if correlate {
		mitigator := initMitigator()
		engine := correlation.New(correlation.Config{
			MaxSources:          td.CorrelationMaxSources,
			MaxSignalsPerSource: td.CorrelationMaxPerSource,
			OnIncident: func(inc correlation.Incident) {
				// Retain in-process so the gateway can surface incidents in its own
				// API/UI (GET /v1/security/incidents) even without an external SIEM.
				correlation.DefaultIncidentStore.Add(inc)
				logIncident(inc)
				// Apply graduated, confidence-aware mitigation (reputation degrade ->
				// restrict -> optional hard shun) to the incident source.
				mitigator.Handle(inc)
				if shipper != nil {
					shipper.Ship(incidentToEvent(inc))
				}
			},
		})
		signals = make(chan correlation.Signal, signalQueueSize)
		go engine.Run(ctx, signals)
	} else {
		logger.L.LogInfo("correlation engine disabled by resource profile",
			"profile", string(config.ResolveProfile()))
	}

	// Only subscribe to the threat broadcaster if there is a consumer: the
	// correlation engine and/or raw SIEM shipping.
	if correlate || shipRaw {
		go consumeThreats(ctx, threatSinks{
			signals: signals, shipper: shipper, shipRaw: shipRaw, correlate: correlate,
		})
	}
}

// publishMitigationAllowlist installs GATEON_MITIGATION_ALLOWLIST where every
// enforcement site reads it: the reputation blocker, the honeypot, the tarpit
// and proof-of-work all ask mitigation.IsAllowlisted.
//
// The list moved to internal/security/mitigation so that it would be a property
// of the deployment rather than a field on one component, but nothing called
// SetAllowlist outside tests, so IsAllowlisted answered false for every address
// and the setting reached only the responder, which parses its own copy.
//
// Entries that do not parse are counted in the log, because an allowlist whose
// only entry has a typo in it is otherwise indistinguishable from no allowlist.
func publishMitigationAllowlist() {
	raw := os.Getenv(envMitigationAllowlist)
	prefixes := mitigation.ParseAllowlist(raw)
	mitigation.SetAllowlist(prefixes)

	entries := 0
	for part := range strings.SplitSeq(raw, ",") {
		if strings.TrimSpace(part) != "" {
			entries++
		}
	}
	if entries == 0 {
		return
	}
	logger.L.LogInfo("mitigation allowlist published to every enforcement site",
		"prefixes", len(prefixes))
	if skipped := entries - len(prefixes); skipped > 0 {
		logger.L.LogWarn("mitigation allowlist entries could not be parsed and are not allowlisted",
			"variable", envMitigationAllowlist, "skipped", skipped)
	}
}

// initSIEMShipper builds and starts the SIEM exporter if configured. Returns
// nil when export is disabled.
func initSIEMShipper(ctx context.Context, version string) *siem.Shipper {
	cfg, err := siem.ConfigFromEnv(version)
	if err != nil {
		return nil // disabled
	}
	shipper, err := siem.New(cfg)
	if err != nil {
		logger.L.LogError("failed to initialize SIEM exporter", "error", err)
		return nil
	}
	go shipper.Run(ctx)
	// Register so the posture endpoint / Security Hub can report SIEM status.
	siem.SetDefault(shipper)
	logger.L.LogInfo("SIEM exporter enabled",
		"endpoint", cfg.Endpoint, "format", string(cfg.Format), "transport", cfg.Transport)
	return shipper
}

// initMitigator builds the graduated incident-mitigation responder from
// environment configuration. Reputation-based mitigation is on by default
// (reversible, self-healing); the hard shun is opt-in via
// GATEON_MITIGATION_AUTO_SHUN.
func initMitigator() *mitigation.Responder {
	enabled := true
	if raw := strings.TrimSpace(os.Getenv(envMitigationEnabled)); raw != "" {
		enabled = boolEnvTrue(envMitigationEnabled)
	}
	cfg := mitigation.Config{
		Enabled:   enabled,
		AutoShun:  boolEnvTrue(envMitigationAutoShun),
		Allowlist: mitigation.ParseAllowlist(os.Getenv(envMitigationAllowlist)),
	}
	if cfg.AutoShun {
		logger.L.LogInfo("incident auto-shun enabled (a lapsing address shun for critical multi-signal incidents)")
	}
	return mitigation.New(cfg, mitigation.Deps{
		Shun: automaticShun{},
		// Compose the scoped identity here rather than inside the responder, so
		// internal/security/mitigation stays free of a telemetry dependency and
		// remains unit-testable without it. DecreaseReputationOf builds it with
		// repid.For and leaves an allowlisted participant's score alone (ADR 0031).
		Degrade: telemetry.DecreaseReputationOf,
		Log: func(action mitigation.Action, inc correlation.Incident, reason string) {
			if action == mitigation.ActionNone || action == mitigation.ActionFlag {
				return // avoid log spam for no-op/flag-only outcomes
			}
			logger.L.LogWarn("incident mitigation applied",
				"action", string(action),
				"source_ip", inc.SourceIP,
				"severity", inc.Severity,
				"signal_types", strings.Join(inc.SignalTypes, ","),
				"reason", reason,
			)
		},
	})
}

// errShunNotApplied is automaticShun's answer for an address it did not shun:
// loopback, allowlisted, or released by an operator within the hold. The
// responder then restricts the incident instead of reporting a shun.
var errShunNotApplied = errors.New("the address is exempt from automatic shuns")

// automaticShun is the responder's hard shun: the automatic shun every other
// path takes, which is recorded, listed with when it lifts, enforced by the
// request path, leased in the kernel, and lapses (ADR 0031). It used to shun
// the address in the kernel directly and then record it, which left a kernel
// entry nothing would lift -- even when the record was refused.
type automaticShun struct{}

func (automaticShun) ShunIP(ip string) error {
	res, err := telemetry.ShunAutomatically(ip, "correlated critical incident (incident responder)")
	if err != nil {
		logger.L.LogError("correlated-incident shun did not persist; the source is not blocked", "ip", ip, "error", err)
		return err
	}
	if !res.Shunned() {
		return errShunNotApplied
	}
	return nil
}

// consumeThreats subscribes to the threat broadcaster and feeds the correlation
// engine, optionally shipping raw threats too.
func consumeThreats(ctx context.Context, sinks threatSinks) {
	ch := telemetry.ThreatBroadcaster.Subscribe()
	defer telemetry.ThreatBroadcaster.Unsubscribe(ch)

	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ch:
			sinks.forward(&t)
		}
	}
}

// threatSinks is where a recorded threat goes after the store: the SIEM
// exporter, as a raw event, and the correlation engine, as a signal.
type threatSinks struct {
	signals   chan<- correlation.Signal
	shipper   *siem.Shipper
	shipRaw   bool
	correlate bool
}

// forward hands one threat to each sink that wants it.
//
// A threat not held against its source is shipped but not correlated: an
// incident's response degrades the source's reputation and can shun it. That
// excludes a threat its source did not choose to send, a match nobody acted on
// (an audit-only WAF), and a refusal of an earlier decision -- a feed listing
// or shun (ADR 0044), a fingerprint block, a reputation refusal -- which is the
// gateway's own decision coming back as "evidence" for the next one
// (telemetry.SecurityThreat.HeldAgainstSource, ADR 0055). Serving a challenge
// records no threat at all (ADR 0045).
func (s threatSinks) forward(t *telemetry.SecurityThreat) {
	if s.shipRaw {
		s.shipper.Ship(threatToEvent(t))
	}
	if s.correlate && t.HeldAgainstSource() {
		select {
		case s.signals <- threatToSignal(t):
		default: // drop on backpressure; never block the broadcaster
		}
	}
}

// threatToSignal adapts a telemetry threat into a correlation signal.
func threatToSignal(t *telemetry.SecurityThreat) correlation.Signal {
	return correlation.Signal{
		Type:        t.Type,
		SourceIP:    t.SourceIP,
		Fingerprint: t.Fingerprint,
		JA4:         t.JA4,
		Score:       t.Score,
		Severity:    t.Severity,
		Category:    t.Category,
		RouteID:     t.RouteID,
		RequestURI:  t.RequestURI,
		CountryCode: t.CountryCode,
		Details:     t.Details,
		Time:        t.Time,
	}
}

// threatToEvent renders a single threat as a SIEM event.
func threatToEvent(t *telemetry.SecurityThreat) siem.Event {
	fields := map[string]string{
		"category": t.Category,
		"action":   t.ActionTaken,
	}
	addField(fields, "route_id", t.RouteID)
	addField(fields, "request_uri", t.RequestURI)
	addField(fields, "country", t.CountryCode)
	addField(fields, "fingerprint", t.Fingerprint)
	addField(fields, "ja4", t.JA4)
	addField(fields, "ja4h", t.JA4H)
	addField(fields, "mitre", techniqueIDs(correlation.Techniques(t.Type)))
	if t.Score != 0 {
		fields["score"] = strconv.FormatFloat(t.Score, 'f', 2, 64)
	}

	return siem.Event{
		Time:     t.Time,
		Kind:     siem.KindThreat,
		Name:     t.Type,
		Severity: t.Severity,
		SourceIP: t.SourceIP,
		Message:  t.Details,
		Fields:   fields,
	}
}

// incidentToEvent renders a correlated incident as a SIEM event.
func incidentToEvent(inc correlation.Incident) siem.Event {
	fields := map[string]string{
		"source_key":   inc.SourceKey,
		"signal_count": strconv.Itoa(inc.SignalCount),
		"score":        strconv.FormatFloat(inc.Score, 'f', 2, 64),
		"signal_types": strings.Join(inc.SignalTypes, ","),
		"mitre":        techniqueIDs(inc.Techniques),
	}
	addField(fields, "fingerprint", inc.Fingerprint)
	addField(fields, "countries", strings.Join(inc.Countries, ","))

	return siem.Event{
		Time:     inc.LastSeen,
		Kind:     siem.KindIncident,
		Name:     "correlated_incident",
		Severity: inc.Severity,
		SourceIP: inc.SourceIP,
		Message: fmt.Sprintf("%d correlated signals (%s) from %s",
			inc.SignalCount, strings.Join(inc.SignalTypes, ","), inc.SourceKey),
		Fields: fields,
	}
}

// logIncident emits a structured warning for a correlated incident so the
// engine is useful even without SIEM export configured.
func logIncident(inc correlation.Incident) {
	logger.L.LogWarn("correlated security incident",
		"id", inc.ID,
		"source", inc.SourceKey,
		"source_ip", inc.SourceIP,
		"severity", inc.Severity,
		"signal_count", inc.SignalCount,
		"signal_types", strings.Join(inc.SignalTypes, ","),
		"mitre", techniqueIDs(inc.Techniques),
		"score", inc.Score,
	)
}

// techniqueIDs joins technique IDs into a comma-separated string.
func techniqueIDs(techniques []correlation.Technique) string {
	if len(techniques) == 0 {
		return ""
	}
	ids := make([]string, 0, len(techniques))
	for _, t := range techniques {
		ids = append(ids, t.ID)
	}
	return strings.Join(ids, ",")
}

// addField sets a SIEM field only when the value is non-empty.
func addField(fields map[string]string, key, value string) {
	if value != "" {
		fields[key] = value
	}
}

// boolEnvTrue reports whether an environment variable parses to a truthy value.
func boolEnvTrue(key string) bool {
	v, err := strconv.ParseBool(strings.TrimSpace(os.Getenv(key)))
	return err == nil && v
}
