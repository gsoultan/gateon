// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
)

// The global-setting effect check (truth NEW-10).
//
// Global settings had no effect rows, so a security threshold that was read
// and then ignored -- the PoW threshold made a constant, the feed's block
// threshold dropped -- passed every gate: it is read, so the dead-field check
// is satisfied, and nothing else looks. These are the global settings that
// decide whom the gateway refuses or challenges; each needs a row in
// internal/router/global_setting_effects_test.go, which builds a route's chain
// under two values and requires different answers, or a line in
// globals-baseline.txt held to the same note rules as the middleware keys.

const (
	globalsRegistryPath = "internal/router/global_setting_effects_test.go"
	globalsBaselinePath = "scripts/checkconfig/globals-baseline.txt"
)

// globalSecuritySettings are the global settings that decide whom the gateway
// refuses, challenges or slows.
var globalSecuritySettings = []string{
	"security_advanced.ip_reputation.block_threshold",
	"security_advanced.pow.difficulty",
	"security_advanced.pow.score_threshold",
	"security_advanced.tarpit.delay_base_ms",
	"security_advanced.tarpit.delay_max_ms",
	"security_advanced.tarpit.score_threshold",
	"security_advanced.entropy.threshold",
	// The gateway-wide WAF's attack families (ADR 0064).
	"waf.categories.sqli",
	"waf.categories.xss",
	"waf.categories.lfi",
	"waf.categories.rce",
	"waf.categories.php",
	"waf.categories.java",
	"waf.categories.nodejs",
	"waf.categories.scanner",
	"waf.categories.protocol",
	"waf.categories.ransomware_detection",
}

// globalRows reads the registry's rows: field -> inert.
func globalRows(path string) (map[string]bool, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return nil, err
	}
	rows := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		if lit, ok := n.(*ast.CompositeLit); ok {
			fields := literalFields(lit)
			if f, ok := fields["field"]; ok {
				_, inert := fields["inert"]
				rows[f] = rows[f] || inert
			}
		}
		return true
	})
	return rows, nil
}

// compareGlobals returns the listed settings with neither a row nor a
// baseline line.
func compareGlobals(required []string, rows map[string]bool, baseline map[string]string) []string {
	var missing []string
	for _, f := range required {
		_, row := rows[f]
		_, base := baseline[f]
		if !row && !base {
			missing = append(missing, f)
		}
	}
	sort.Strings(missing)
	return missing
}

// checkGlobals runs the check; true when a listed setting is uncovered or a
// baseline note does not hold.
func checkGlobals(idx testIndex) bool {
	rows, err := globalRows(globalsRegistryPath)
	if err != nil {
		fatalf("reading the global effect registry: %v", err)
	}
	notes, err := loadNotedBaseline(globalsBaselinePath)
	if err != nil {
		fatalf("reading the globals baseline: %v", err)
	}
	failed := reportNotes(notes, idx)
	missing := compareGlobals(globalSecuritySettings, rows, notes)
	if len(missing) == 0 {
		proven := 0
		for _, f := range globalSecuritySettings {
			if _, ok := rows[f]; ok {
				proven++
			}
		}
		fmt.Printf("ok - %d global security settings: %d proven by an effect test, %d baselined\n",
			len(globalSecuritySettings), proven, len(globalSecuritySettings)-proven)
		return failed
	}
	reportList(missing, "global security settings with no effect test", fmt.Sprintf(
		"Add a row to %s that sets it to two values and shows the gateway answering differently,\nor a line in %s saying why not yet.",
		globalsRegistryPath, globalsBaselinePath))
	return true
}
