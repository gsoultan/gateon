// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware/security"
)

// The attack probes the 2026-10-02 review drove through a live gateway
// (/tmp/rv-truth/t1_waf.py), one per category switch. Each is blocked by a
// route WAF with no configuration.
var categoryProbes = map[string]func() *http.Request{
	"sqli":    func() *http.Request { return probeGET("/?id=" + url.QueryEscape("1' OR '1'='1' -- ")) },
	"xss":     func() *http.Request { return probeGET("/?q=" + url.QueryEscape("<script>alert(1)</script>")) },
	"lfi":     func() *http.Request { return probeGET("/?f=" + url.QueryEscape("../../../../etc/passwd")) },
	"rce":     func() *http.Request { return probeGET("/?c=" + url.QueryEscape(";uname -a")) },
	"php":     func() *http.Request { return probeGET("/?x=" + url.QueryEscape(`<?php system($_GET["c"]); ?>`)) },
	"java":    func() *http.Request { return probeGET("/?q=" + url.QueryEscape("java.lang.Runtime")) },
	"nodejs":  func() *http.Request { return probeGET("/?q=" + url.QueryEscape("process.mainModule")) },
	"scanner": func() *http.Request { return probeUA("sqlmap/1.7.2#stable (https://sqlmap.org)") },
}

// sqliJSONProbe is the SQL injection in a JSON body: the body phase runs its
// own copies of the core rules, and a switch has to reach those too.
func sqliJSONProbe() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"id":"1' OR '1'='1' -- "}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/129.0 Safari/537.36")
	return r
}

func probeGET(target string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/129.0 Safari/537.36")
	r.Header.Set("Accept", "text/html")
	return r
}

func probeUA(ua string) *http.Request {
	r := probeGET("/")
	r.Header.Set("User-Agent", ua)
	return r
}

// routeWAFStatus builds a route WAF through the factory the router uses and
// returns the status it gives probe.
func routeWAFStatus(t *testing.T, cfg map[string]string, d security.Deps, probe func() *http.Request) int {
	t.Helper()
	mw, err := NewWAF(cfg, d)
	if err != nil {
		t.Fatalf("NewWAF(%v): %v", cfg, err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, probe())
	return rr.Code
}

// TestRouteWAFCategorySwitchTurnsItsCategoryOff is truth T8: every category
// switch on a route WAF was inert. With sqli=false a SQL injection was still
// refused -- by gwaf's core "SQL injection (structural)" rule, which the
// switch never reached -- and the same for XSS, LFI, RCE, PHP and scanners.
// Each switch now lets its own family through and nothing else: the other
// families stay refused, so the switch narrows exactly what it names.
func TestRouteWAFCategorySwitchTurnsItsCategoryOff(t *testing.T) {
	InvalidateWAFCache()
	t.Cleanup(InvalidateWAFCache)
	for name, probe := range categoryProbes {
		t.Run(name+" on", func(t *testing.T) {
			if got := routeWAFStatus(t, map[string]string{"route": "sw-on"}, security.Deps{}, probe); got != http.StatusForbidden {
				t.Fatalf("%s probe with the switch on: got %d, want 403", name, got)
			}
		})
		t.Run(name+" off", func(t *testing.T) {
			cfg := map[string]string{"route": "sw-off-" + name, name: "false"}
			if got := routeWAFStatus(t, cfg, security.Deps{}, probe); got != http.StatusOK {
				t.Fatalf("%s probe with %s=false: got %d, want 200 -- the switch does not reach the rules that block it", name, name, got)
			}
			for other, otherProbe := range categoryProbes {
				if other == name || coveredByOther(name, other) {
					continue
				}
				if got := routeWAFStatus(t, cfg, security.Deps{}, otherProbe); got != http.StatusForbidden {
					t.Errorf("%s=false let the %s probe through (%d): a switch must narrow only its own family", name, other, got)
				}
			}
		})
	}
}

// coveredByOther names the probes a switch legitimately reaches beyond its
// own: PHP, Java and Node.js code injection are code execution, so turning RCE
// off lets those probes through as well. The reverse does not hold -- turning
// Java off leaves RCE's own Log4Shell rule in force.
func coveredByOther(off, probe string) bool {
	return off == "rce" && (probe == "php" || probe == "java" || probe == "nodejs")
}

// TestRouteWAFAllCategoriesOffStillBlocksWhatNoSwitchNames pins the other
// half: switching every category off is not switching the WAF off. A probe no
// switch names is still refused, so the switches cannot be used to empty the
// engine by accident.
func TestRouteWAFAllCategoriesOffStillBlocksWhatNoSwitchNames(t *testing.T) {
	InvalidateWAFCache()
	t.Cleanup(InvalidateWAFCache)
	cfg := map[string]string{"route": "all-off"}
	for _, k := range []string{"sqli", "xss", "lfi", "rce", "php", "scanner", "protocol", "java", "nodejs", "wordpress"} {
		cfg[k] = "false"
	}
	for name, probe := range categoryProbes {
		if got := routeWAFStatus(t, cfg, security.Deps{}, probe); got != http.StatusOK {
			t.Errorf("%s probe with every category off: got %d, want 200", name, got)
		}
	}
	// SSRF to cloud metadata belongs to no category switch.
	if got := routeWAFStatus(t, cfg, security.Deps{}, sqliJSONProbe); got != http.StatusOK {
		t.Errorf("SQL injection in a JSON body with every category off: got %d, want 200", got)
	}
	ssrf := func() *http.Request {
		return probeGET("/?u=" + url.QueryEscape("http://169.254.169.254/latest/meta-data/"))
	}
	if got := routeWAFStatus(t, cfg, security.Deps{}, ssrf); got != http.StatusForbidden {
		t.Errorf("cloud-metadata SSRF with every category off: got %d, want 403", got)
	}
}
