// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware/security"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// dashboardGlobalWAF is the global WAF object the dashboard writes when an
// operator switches "Protect all routes" on: every category boolean and
// malware/ransomware at their zero value.
func dashboardGlobalWAF() security.Deps {
	return security.Deps{GlobalStore: &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{
		Waf: &gateonv1.WafConfig{Enabled: true, UseCrs: true, ParanoiaLevel: 1},
	}}}
}

// The malware and ransomware probes of the review (/tmp/rv-truth/t4.py).
func webshellProbe() *http.Request   { return probeGET("/c99.php") }
func ransomNoteProbe() *http.Request { return probeGET("/decrypt_files.txt") }
func globalWAFStatus(t *testing.T, d security.Deps, probe func() *http.Request) int {
	t.Helper()
	mw, err := NewGlobalWAF(d)
	if err != nil || mw == nil {
		t.Fatalf("NewGlobalWAF: %v (nil=%v)", err, mw == nil)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, probe())
	return rr.Code
}

// TestRouteWAFKeepsWhatTheGlobalWAFRuns is truth T7: with the global WAF on, a
// route that attached a WAF with no configuration lost the malware and
// ransomware rules the global WAF had been running on it -- /c99.php and
// /decrypt_files.txt went from 403 to 200. The route WAF replaces the global
// one, and it inherited the raw proto booleans (false) instead of what the
// global WAF runs (on). A route's WAF now starts from the effective global
// policy.
func TestRouteWAFKeepsWhatTheGlobalWAFRuns(t *testing.T) {
	InvalidateWAFCache()
	t.Cleanup(InvalidateWAFCache)
	d := dashboardGlobalWAF()
	for name, probe := range map[string]func() *http.Request{"webshell": webshellProbe, "ransom note": ransomNoteProbe} {
		if got := globalWAFStatus(t, d, probe); got != http.StatusForbidden {
			t.Fatalf("precondition: the global WAF gives the %s probe %d, want 403", name, got)
		}
		if got := routeWAFStatus(t, map[string]string{"route": "w"}, d, probe); got != http.StatusForbidden {
			t.Errorf("a default route WAF under the global WAF gives the %s probe %d, want 403 "+
				"(attaching a WAF to a route must not drop rules the global WAF runs there)", name, got)
		}
	}
}

// TestRouteWAFNarrowsOnlyWhenItSaysSo is the other half of the merge rule: a
// route that names a setting gets it. Switching malware detection off on one
// route is allowed -- it is explicit, and the effective view shows it -- and
// only that route loses it.
func TestRouteWAFNarrowsOnlyWhenItSaysSo(t *testing.T) {
	InvalidateWAFCache()
	t.Cleanup(InvalidateWAFCache)
	d := dashboardGlobalWAF()
	cfg := map[string]string{"route": "narrow", "malware_detection": "false"}
	if got := routeWAFStatus(t, cfg, d, webshellProbe); got != http.StatusOK {
		t.Errorf("route with malware_detection=false: webshell probe got %d, want 200", got)
	}
	if got := routeWAFStatus(t, cfg, d, ransomNoteProbe); got != http.StatusForbidden {
		t.Errorf("route with malware_detection=false: ransom-note probe got %d, want 403 (ransomware is still inherited)", got)
	}
}

// TestRouteWAFInheritsParanoiaAndEnforcement pins two more settings the route
// used to drop silently: the global paranoia level, and enforcement itself. A
// route WAF that says nothing about audit_only enforces when the global WAF
// does; one that asks for audit-only gets it.
func TestRouteWAFInheritsParanoiaAndEnforcement(t *testing.T) {
	d := security.Deps{GlobalStore: &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{
		Waf: &gateonv1.WafConfig{Enabled: true, UseCrs: true, ParanoiaLevel: 3},
	}}}
	cfg := map[string]string{}
	mergeGlobalWAFDefaults(cfg, d)
	got := parseWAFConfig(cfg)
	if got.ParanoiaLevel != 3 {
		t.Errorf("route WAF paranoia level = %d, want the global 3", got.ParanoiaLevel)
	}
	if got.AuditOnly {
		t.Error("route WAF under an enforcing global WAF is audit-only")
	}
	if !got.EnableMalwareDetection || !got.EnableRansomwareDetection {
		t.Errorf("route WAF malware=%v ransomware=%v, want both inherited on", got.EnableMalwareDetection, got.EnableRansomwareDetection)
	}

	explicit := map[string]string{"audit_only": "true", "paranoia_level": "1"}
	mergeGlobalWAFDefaults(explicit, d)
	if got := parseWAFConfig(explicit); !got.AuditOnly || got.ParanoiaLevel != 1 {
		t.Errorf("explicit route settings: audit_only=%v paranoia=%d, want true and 1", got.AuditOnly, got.ParanoiaLevel)
	}
}
