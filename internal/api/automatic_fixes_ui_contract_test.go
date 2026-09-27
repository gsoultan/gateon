// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
)

// TestTheDashboardOffersExactlyTheFixesTheGatewayHas holds the finding types
// the dashboard offers "Apply automatic fix" for to the ones
// ApplyRecommendation acts on.
//
// Nothing ties them together otherwise: the list is written by hand in
// TypeScript, and a type offered without a fix answers "not implemented" to
// the click -- which is what nine of the engine's types did, honeypot_triggered
// among them, while a fix with no button is a fix nobody can reach.
func TestTheDashboardOffersExactlyTheFixesTheGatewayHas(t *testing.T) {
	path := filepath.Join("..", "..", "ui", "src", "components", "SecurityCenter", "automaticFixes.ts")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the dashboard's list: %v", err)
	}
	block := regexp.MustCompile(`(?s)AUTOMATIC_FIX_TYPES: ReadonlySet<string> = new Set\(\[\n(.*?)\n\]\);`).FindSubmatch(src)
	if block == nil {
		t.Fatalf("%s declares no AUTOMATIC_FIX_TYPES set", path)
	}
	var offered []string
	for _, m := range regexp.MustCompile(`(?m)^  "([a-z_]+)",$`).FindAllSubmatch(block[1], -1) {
		offered = append(offered, string(m[1]))
	}
	implemented := slices.Sorted(maps.Keys(recommendationFixes))
	slices.Sort(offered)

	for _, typ := range offered {
		if !slices.Contains(implemented, typ) {
			t.Errorf("the dashboard offers a fix for %s, which ApplyRecommendation has none for", typ)
		}
	}
	for _, typ := range implemented {
		if !slices.Contains(offered, typ) {
			t.Errorf("ApplyRecommendation can fix %s, but the dashboard never offers it", typ)
		}
	}
}
