package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/security/correlation"
	"github.com/gsoultan/gateon/internal/security/fim"
	"github.com/gsoultan/gateon/internal/security/siem"
)

// SecurityPostureProvider produces the current security posture report. It is
// supplied by the server wiring (which holds the subsystem managers) so the
// handler package stays decoupled from those concrete managers.
type SecurityPostureProvider func(context.Context) *SecurityPostureReport

// SecurityPostureReport is the JSON payload returned by GET /v1/security/posture.
// It summarizes the freshness and health of Gateon's defensive subsystems so
// operators (and external SIEMs) can assess detection coverage at a glance.
type SecurityPostureReport struct {
	Version     string            `json:"version"`
	GeneratedAt time.Time         `json:"generated_at"`
	WAF         WAFPosture        `json:"waf"`
	ClamAV      ClamAVPosture     `json:"clamav"`
	Signatures  SignaturePosture  `json:"signatures"`
	SIEM        siem.StatusReport `json:"siem"`
	FIM         *fim.Status       `json:"fim,omitzero"`
}

// SignaturePosture reports the dependency-free YARA-lite upload signature engine
// state (built-in + any loaded custom rules).
type SignaturePosture struct {
	Enabled   bool `json:"enabled"`
	RuleCount int  `json:"rule_count"`
}

// WAFPosture reports WAF rule-set freshness.
type WAFPosture struct {
	Enabled     bool      `json:"enabled"`
	AutoUpdate  bool      `json:"auto_update"`
	LastUpdated time.Time `json:"last_updated,omitzero"`
}

// ClamAVPosture reports antivirus engine availability and scan freshness.
type ClamAVPosture struct {
	Enabled    bool      `json:"enabled"`
	Installed  bool      `json:"installed"`
	LastScan   time.Time `json:"last_scan,omitzero"`
	LastResult string    `json:"last_result,omitzero"`
	LastError  string    `json:"last_error,omitzero"`
}

// registerSecurityHandlers wires the security posture and correlated-incidents
// endpoints.
func registerSecurityHandlers(mux *http.ServeMux, d *Deps) {
	mux.HandleFunc("GET /v1/security/posture", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceDiagnostics) {
			return
		}
		report := d.buildPostureReport(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(report)
	})

	// Correlated incidents are higher-level findings raised by the correlation
	// engine when multiple related detections from one source cross a threshold,
	// annotated with MITRE ATT&CK techniques. They are retained in-process so the
	// Security Hub can surface them without an external SIEM.
	mux.HandleFunc("GET /v1/security/incidents", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceDiagnostics) {
			return
		}
		limit := 100
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				limit = n
			}
		}
		incidents := correlation.DefaultIncidentStore.List(limit)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"incidents":    incidents,
			"total_seen":   correlation.DefaultIncidentStore.TotalSeen(),
			"retained":     correlation.DefaultIncidentStore.Len(),
			"generated_at": time.Now(),
		})
	})
}

// buildPostureReport returns the posture from the configured provider, falling
// back to a minimal report (version + timestamp) when no provider is wired so
// the endpoint never 500s on a partially-initialized server.
func (d *Deps) buildPostureReport(ctx context.Context) *SecurityPostureReport {
	if d.SecurityPosture != nil {
		if report := d.SecurityPosture(ctx); report != nil {
			return report
		}
	}
	return &SecurityPostureReport{Version: d.Version, GeneratedAt: time.Now()}
}
