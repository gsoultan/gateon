// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware/security"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// globalWith is a dashboard-shaped enabled global WAF with categories c.
func globalWith(c *gateonv1.WafCategories) security.Deps {
	return security.Deps{GlobalStore: &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{
		Waf: &gateonv1.WafConfig{Enabled: true, ParanoiaLevel: 1, Categories: c},
	}}}
}

// off is a pointer to false, a switch set explicitly off.
func off() *bool { v := false; return &v }

// categoryOff is a WafCategories with family name explicitly off.
func categoryOff(t *testing.T, name string) *gateonv1.WafCategories {
	t.Helper()
	c := &gateonv1.WafCategories{}
	switch name {
	case "sqli":
		c.Sqli = off()
	case "xss":
		c.Xss = off()
	case "lfi":
		c.Lfi = off()
	case "rce":
		c.Rce = off()
	case "php":
		c.Php = off()
	case "java":
		c.Java = off()
	case "nodejs":
		c.Nodejs = off()
	case "scanner":
		c.Scanner = off()
	default:
		t.Fatalf("no switch for %s", name)
	}
	return c
}

// TestGlobalWAFCategorySwitchTurnsItsFamilyOff is ADR 0064: the gateway-wide
// WAF's category switches used to be read by nothing -- it ran every family
// whatever they said (ADR 0044). An explicit off now removes that family, and
// only that family, with the mapping a route WAF's switch uses: every probe
// gets the answer a route WAF with the same switch off gives, the family's own
// probe goes through, the other families stay refused, and the web-shell rule
// (a malware rule that also carries the rce tag) stays refused whichever
// family is off (ADR 0063 NEW-9).
//
// The PHP probe is a PHP web shell in a parameter, which the malware rules the
// global WAF always runs refuse too -- as does a route WAF over the same
// global config -- so for PHP only the equality is asserted.
func TestGlobalWAFCategorySwitchTurnsItsFamilyOff(t *testing.T) {
	InvalidateWAFCache()
	t.Cleanup(InvalidateWAFCache)
	for name, probe := range categoryProbes {
		t.Run(name, func(t *testing.T) {
			if got := globalWAFStatus(t, globalWith(nil), probe); got != http.StatusForbidden {
				t.Fatalf("precondition: %s probe with no switch set: got %d, want 403", name, got)
			}
			d := globalWith(categoryOff(t, name))
			if got := globalWAFStatus(t, d, probe); got != http.StatusOK && name != "php" {
				t.Fatalf("%s probe with the global %s switch off: got %d, want 200", name, name, got)
			}
			routeCfg := map[string]string{"route": "same-map-" + name, name: "false"}
			for other, otherProbe := range categoryProbes {
				got := globalWAFStatus(t, d, otherProbe)
				if want := routeWAFStatus(t, routeCfg, globalWith(nil), otherProbe); got != want {
					t.Errorf("global %s off: %s probe got %d, a route WAF with %s=false gives %d", name, other, got, name, want)
				}
				if other == name || coveredByOther(name, other) {
					continue
				}
				if got != http.StatusForbidden {
					t.Errorf("global %s off let the %s probe through (%d)", name, other, got)
				}
			}
			if got := globalWAFStatus(t, d, webshellProbe); got != http.StatusForbidden {
				t.Errorf("global %s off: GET /c99.php got %d, want 403 -- a family switch removed a malware rule", name, got)
			}
		})
	}
	t.Run("ransomware_detection", func(t *testing.T) {
		if got := globalWAFStatus(t, globalWith(nil), ransomNoteProbe); got != http.StatusForbidden {
			t.Fatalf("precondition: ransom note with no switch set: got %d, want 403", got)
		}
		d := globalWith(&gateonv1.WafCategories{RansomwareDetection: off()})
		if got := globalWAFStatus(t, d, ransomNoteProbe); got != http.StatusOK {
			t.Fatalf("ransom note with ransomware_detection off: got %d, want 200", got)
		}
	})
}

// TestAnExplicitOnRunsAFamilyTheTierDrops: unset leaves a family to the tier,
// and the minimal tier drops LFI; an explicit true runs it anyway.
func TestAnExplicitOnRunsAFamilyTheTierDrops(t *testing.T) {
	InvalidateWAFCache()
	t.Cleanup(InvalidateWAFCache)
	on := true
	minimal := func(c *gateonv1.WafCategories) security.Deps {
		return security.Deps{GlobalStore: &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{
			Waf: &gateonv1.WafConfig{Enabled: true, Tier: "minimal", Categories: c},
		}}}
	}
	probe := categoryProbes["lfi"]
	if got := globalWAFStatus(t, minimal(nil), probe); got != http.StatusOK {
		t.Fatalf("precondition: the minimal tier gives the LFI probe %d, want 200", got)
	}
	if got := globalWAFStatus(t, minimal(&gateonv1.WafCategories{Lfi: &on}), probe); got != http.StatusForbidden {
		t.Fatalf("lfi=true at the minimal tier: got %d, want 403", got)
	}
}

// TestARouteWAFKeepsPrecedenceOverTheGlobalSwitches: a route WAF starts from
// the global WAF (ADR 0044). A switch it leaves unset inherits the global
// one, off included; a switch it sets wins.
func TestARouteWAFKeepsPrecedenceOverTheGlobalSwitches(t *testing.T) {
	InvalidateWAFCache()
	t.Cleanup(InvalidateWAFCache)
	d := globalWith(&gateonv1.WafCategories{Sqli: off()})
	probe := categoryProbes["sqli"]
	if got := routeWAFStatus(t, map[string]string{"route": "inherits"}, d, probe); got != http.StatusOK {
		t.Errorf("route WAF with sqli unset under a global sqli off: got %d, want 200 (inherited)", got)
	}
	if got := routeWAFStatus(t, map[string]string{"route": "own", "sqli": "true"}, d, probe); got != http.StatusForbidden {
		t.Errorf("route WAF with sqli=true under a global sqli off: got %d, want 403 (its own switch wins)", got)
	}
}

// TestEffectiveGlobalReportsTheCategorySwitches: /v1/waf/effective reads the
// engine's config, so it says a switched-off family is off and the rest on.
func TestEffectiveGlobalReportsTheCategorySwitches(t *testing.T) {
	d := globalWith(&gateonv1.WafCategories{Xss: off(), RansomwareDetection: off()})
	e := EffectiveGlobal(context.Background(), d.GlobalStore)
	for k, want := range map[string]bool{"xss": false, keyRansomware: false, "sqli": true, keyMalware: true} {
		if e.Categories[k] != want {
			t.Errorf("effective %s = %v, want %v", k, e.Categories[k], want)
		}
	}
}

// v110GlobalJSON is a global.json as v1.1.0 could have stored it: use_crs and
// the old category booleans, some false -- written so by a GET-then-PUT of the
// API, which emits every field, or by hand -- some true.
const v110GlobalJSON = `{
  "waf": {
    "enabled": true,
    "use_crs": true,
    "paranoia_level": 1,
    "sqli": false, "xss": false, "lfi": false, "rce": false, "php": false,
    "scanner": false, "protocol": true, "java": false, "nodejs": false,
    "ransomware_detection": false
  }
}`

// v110GlobalYAML is the same as yaml.v3 wrote it from the generated struct,
// which has no yaml tags: every field, lower-cased, false ones included.
const v110GlobalYAML = `waf:
  enabled: true
  usecrs: true
  paranoialevel: 1
  sqli: false
  xss: false
  lfi: false
  rce: false
  php: false
  scanner: false
  protocol: false
  java: false
  nodejs: false
  ransomwaredetection: false
`

// TestAGlobalConfigStoredByV110RunsEveryCategory is the upgrade trap: the old
// booleans had no presence, so a stored false meant "nobody touched it" as
// often as "off", and the gateway-wide WAF ran every family whatever they
// said. The switches that replace them are new fields under new tags, so no
// file v1.1.0 wrote can read as off: every family still runs after upgrade.
func TestAGlobalConfigStoredByV110RunsEveryCategory(t *testing.T) {
	for name, file := range map[string]struct{ path, body string }{
		"json": {"global.json", v110GlobalJSON},
		"yaml": {"global.yaml", v110GlobalYAML},
	} {
		t.Run(name, func(t *testing.T) {
			InvalidateWAFCache()
			t.Cleanup(InvalidateWAFCache)
			path := filepath.Join(t.TempDir(), file.path)
			if err := os.WriteFile(path, []byte(file.body), 0o600); err != nil {
				t.Fatal(err)
			}
			reg := config.NewGlobalRegistry(path)
			if err := reg.LoadErr(); err != nil {
				t.Fatalf("a v1.1.0 global config no longer loads: %v", err)
			}
			if c := reg.Get(context.Background()).GetWaf().GetCategories(); c != nil {
				t.Fatalf("a v1.1.0 config read as category switches %v; the old booleans must mean nothing", c)
			}
			e := EffectiveGlobal(context.Background(), reg)
			for _, k := range effectiveCategoryKeys {
				if k == keyWordPress || k == keyDLP || k == keyIPReputation {
					continue // opt-in on the global WAF, as before
				}
				if !e.Categories[k] {
					t.Errorf("after upgrade the global WAF reports %s off", k)
				}
			}
			d := security.Deps{GlobalStore: reg}
			for probeName, probe := range categoryProbes {
				if got := globalWAFStatus(t, d, probe); got != http.StatusForbidden {
					t.Errorf("after upgrade the %s probe got %d, want 403", probeName, got)
				}
			}
		})
	}
}

// TestAGlobalCategorySwitchSurvivesASaveAndReload: an explicit off is written
// as false and read back as false, in both file formats; an unset switch is
// written as nothing that reads back as off.
func TestAGlobalCategorySwitchSurvivesASaveAndReload(t *testing.T) {
	for _, file := range []string{"global.json", "global.yaml"} {
		t.Run(file, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), file)
			reg := config.NewGlobalRegistry(path)
			cfg := reg.Get(context.Background())
			cfg.Waf = &gateonv1.WafConfig{Enabled: true, Categories: &gateonv1.WafCategories{Lfi: off()}}
			if err := reg.Update(context.Background(), cfg); err != nil {
				t.Fatalf("save: %v", err)
			}
			c := config.NewGlobalRegistry(path).Get(context.Background()).GetWaf().GetCategories()
			if c.Lfi == nil || *c.Lfi {
				t.Fatalf("lfi after reload = %v, want explicit false", c.Lfi)
			}
			if c.Sqli != nil {
				t.Fatalf("sqli after reload = %v, want unset", *c.Sqli)
			}
		})
	}
}
