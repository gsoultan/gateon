package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

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
func startThreatPipeline(ctx context.Context, version string, shun mitigation.Shunner) {
	shipper := initSIEMShipper(ctx, version)
	shipRaw := shipper != nil && boolEnvTrue(envShipRawThreats)
	mitigator := initMitigator(shun)

	engine := correlation.New(correlation.Config{
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

	signals := make(chan correlation.Signal, signalQueueSize)
	go engine.Run(ctx, signals)
	go consumeThreats(ctx, signals, shipper, shipRaw)
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
// (reversible, self-healing); hard eBPF shunning is opt-in via
// GATEON_MITIGATION_AUTO_SHUN.
func initMitigator(shun mitigation.Shunner) *mitigation.Responder {
	enabled := true
	if raw := strings.TrimSpace(os.Getenv(envMitigationEnabled)); raw != "" {
		enabled = boolEnvTrue(envMitigationEnabled)
	}
	cfg := mitigation.Config{
		Enabled:   enabled,
		AutoShun:  boolEnvTrue(envMitigationAutoShun),
		Allowlist: mitigation.ParseAllowlist(os.Getenv(envMitigationAllowlist)),
	}
	if cfg.AutoShun && shun != nil {
		logger.L.LogInfo("incident auto-shun enabled (hard eBPF block for critical multi-signal incidents)")
	}
	return mitigation.New(cfg, mitigation.Deps{
		Shun:    shun,
		Degrade: telemetry.DecreaseReputation,
		Mark:    telemetry.MarkIPMitigated,
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

// consumeThreats subscribes to the threat broadcaster and feeds the correlation
// engine, optionally shipping raw threats too.
func consumeThreats(ctx context.Context, signals chan<- correlation.Signal, shipper *siem.Shipper, shipRaw bool) {
	ch := telemetry.ThreatBroadcaster.Subscribe()
	defer telemetry.ThreatBroadcaster.Unsubscribe(ch)

	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ch:
			if shipRaw {
				shipper.Ship(threatToEvent(t))
			}
			select {
			case signals <- threatToSignal(t):
			default: // drop on backpressure; never block the broadcaster
			}
		}
	}
}

// threatToSignal adapts a telemetry threat into a correlation signal.
func threatToSignal(t telemetry.SecurityThreat) correlation.Signal {
	return correlation.Signal{
		Type:        t.Type,
		SourceIP:    t.SourceIP,
		Fingerprint: t.Fingerprint,
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
func threatToEvent(t telemetry.SecurityThreat) siem.Event {
	fields := map[string]string{
		"category": t.Category,
		"action":   t.ActionTaken,
	}
	addField(fields, "route_id", t.RouteID)
	addField(fields, "request_uri", t.RequestURI)
	addField(fields, "country", t.CountryCode)
	addField(fields, "fingerprint", t.Fingerprint)
	addField(fields, "ja3", t.JA3)
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
