// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package posture

import (
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func no() *bool { v := false; return &v }

// everyFamilyOff is a global WafCategories with every attack family off.
func everyFamilyOff() *gateonv1.WafCategories {
	return &gateonv1.WafCategories{Sqli: no(), Xss: no(), Lfi: no(), Rce: no(), Php: no(),
		Java: no(), Nodejs: no(), Scanner: no(), Protocol: no()}
}

// TestAGlobalWAFWithEveryFamilyOffEarnsNoCredit is ADR 0064 in the posture: a
// gateway-wide WAF whose category switches turn every attack family off
// refuses none of those attacks, so -- as for a route WAF (NEW-13) -- the
// routes it covers count under categoriesOff and earn nothing, and a route WAF
// that leaves its switches unset inherits that. One family left on keeps the
// credit, and the detail names what is off.
func TestAGlobalWAFWithEveryFamilyOffEarnsNoCredit(t *testing.T) {
	allOff := &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{Enabled: true, Categories: everyFamilyOff()}}
	oneOn := everyFamilyOff()
	oneOn.Xss = nil
	partly := &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{Enabled: true, Categories: oneOn}}
	inheriting := index(mw("w-plain", "waf", map[string]string{}))
	cases := []struct {
		name       string
		global     *gateonv1.GlobalConfig
		route      *gateonv1.Route
		catsOff    int
		wantCredit float64
	}{
		{"every family off, no route WAF", allOff, httpRoute("r"), 1, 0},
		{"every family off, route WAF inherits", allOff, httpRoute("r", "w-plain"), 1, 0},
		{"xss left unset", partly, httpRoute("r"), 0, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{Global: tc.global, Routes: []*gateonv1.Route{tc.route}, Middlewares: inheriting}
			if cov := Coverage(c); cov.CategoriesOff != tc.catsOff {
				t.Fatalf("coverage = %+v, want categoriesOff %d", cov, tc.catsOff)
			}
			ctl := controlByID(t, Compute(c), "waf")
			if ctl.Credit != tc.wantCredit {
				t.Errorf("WAF credit = %v, want %v", ctl.Credit, tc.wantCredit)
			}
			if !strings.Contains(ctl.Detail, "gateway-wide WAF has sqli") {
				t.Errorf("detail does not name the families switched off: %q", ctl.Detail)
			}
		})
	}
	if got := GlobalWAFMode(allOff.GetWaf()); got != ModeNoCategories {
		t.Errorf("GlobalWAFMode = %s, want %s", got, ModeNoCategories)
	}
	withWordPress := &gateonv1.WafConfig{Enabled: true, Wordpress: true, Categories: everyFamilyOff()}
	if got := GlobalWAFMode(withWordPress); got != ModeEnforce {
		t.Errorf("every family off but WordPress on: GlobalWAFMode = %s, want %s", got, ModeEnforce)
	}
}

// TestAnUnsetGlobalSwitchIsNotOff: a global WAF with no switches set -- every
// install upgraded from v1.1.0 -- earns full credit and names nothing off.
func TestAnUnsetGlobalSwitchIsNotOff(t *testing.T) {
	g := &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{Enabled: true, Categories: &gateonv1.WafCategories{}}}
	c := Config{Global: g, Routes: []*gateonv1.Route{httpRoute("r")}}
	ctl := controlByID(t, Compute(c), "waf")
	if ctl.Credit != 1 || strings.Contains(ctl.Detail, "switched off") {
		t.Fatalf("credit %v, detail %q: an unset switch read as off", ctl.Credit, ctl.Detail)
	}
}

// TestTheGlobalWAFResolverDecides: with a GlobalWAF resolver -- the server
// passes the engine's own reading, tier included -- its answer stands for
// routes without a WAF of their own.
func TestTheGlobalWAFResolverDecides(t *testing.T) {
	g := &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{Enabled: true}}
	c := Config{Global: g, Routes: []*gateonv1.Route{httpRoute("r")},
		GlobalWAF: func() Mode { return ModeNoCategories }}
	if cov := Coverage(c); cov.CategoriesOff != 1 {
		t.Fatalf("coverage = %+v, want the resolver's no_categories counted", cov)
	}
	if got := GlobalMode(c); got != ModeNoCategories {
		t.Fatalf("GlobalMode = %s", got)
	}
}
