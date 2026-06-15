package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/security/fim"
)

// SecurityPostureProvider produces the current security posture report. It is
// supplied by the server wiring (which holds the subsystem managers) so the
// handler package stays decoupled from those concrete managers.
type SecurityPostureProvider func(context.Context) *SecurityPostureReport

// SecurityPostureReport is the JSON payload returned by GET /v1/security/posture.
// It summarizes the freshness and health of Gateon's defensive subsystems so
// operators (and external SIEMs) can assess detection coverage at a glance.
type SecurityPostureReport struct {
	Version     string           `json:"version"`
	GeneratedAt time.Time        `json:"generated_at"`
	WAF         WAFPosture       `json:"waf"`
	ClamAV      ClamAVPosture    `json:"clamav"`
	Signatures  SignaturePosture `json:"signatures"`
	FIM         *fim.Status      `json:"fim,omitzero"`
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

// registerSecurityHandlers wires the security posture endpoint.
func registerSecurityHandlers(mux *http.ServeMux, d *Deps) {
	mux.HandleFunc("GET /v1/security/posture", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceGlobal) {
			return
		}
		report := d.buildPostureReport(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(report)
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
