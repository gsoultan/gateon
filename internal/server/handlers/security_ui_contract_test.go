// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/security/posture"
)

// TestSecurityPostureJSONMatchesTheDashboardTypes holds the posture report's
// JSON names to ui/src/hooks/useSecurityPosture.ts, which is written by hand.
// The report's documentation had already drifted from it once (auto_update
// against autoUpdate, T26); a field spelled one way here and another there
// compiles on both sides and reads as undefined.
func TestSecurityPostureJSONMatchesTheDashboardTypes(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "ui", "src", "hooks", "useSecurityPosture.ts"))
	if err != nil {
		t.Fatalf("read the dashboard's posture types: %v", err)
	}
	pairs := map[string]reflect.Type{
		"SecurityPosture":  reflect.TypeFor[SecurityPostureReport](),
		"WafPosture":       reflect.TypeFor[WAFPosture](),
		"RouteCoverage":    reflect.TypeFor[posture.RouteCoverage](),
		"SignaturePosture": reflect.TypeFor[SignaturePosture](),
		"ClamavPosture":    reflect.TypeFor[ClamAVPosture](),
		"EbpfPosture":      reflect.TypeFor[EbpfPosture](),
		"PostureScore":     reflect.TypeFor[posture.Score](),
		"PostureControl":   reflect.TypeFor[posture.Control](),
	}
	for tsName, typ := range pairs {
		t.Run(tsName, func(t *testing.T) {
			wire, dashboard := postureJSONNames(typ), tsInterfaceFields(t, string(src), tsName)
			for _, name := range wire {
				if !slices.Contains(dashboard, name) {
					t.Errorf("the gateway sends %s.%s; the dashboard's type has no such field", tsName, name)
				}
			}
			for _, name := range dashboard {
				if !slices.Contains(wire, name) {
					t.Errorf("the dashboard reads %s.%s; the gateway never sends it", tsName, name)
				}
			}
		})
	}
}

func postureJSONNames(typ reflect.Type) []string {
	var out []string
	for f := range typ.Fields() {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name != "" && name != "-" {
			out = append(out, name)
		}
	}
	return out
}

// tsInterfaceFields lists the properties of `export interface <name> {...}`.
func tsInterfaceFields(t *testing.T, src, name string) []string {
	t.Helper()
	block := regexp.MustCompile(`(?s)export interface ` + name + ` \{\n(.*?)\n\}`).FindStringSubmatch(src)
	if block == nil {
		t.Fatalf("useSecurityPosture.ts declares no interface %s", name)
	}
	var fields []string
	for _, m := range regexp.MustCompile(`(?m)^  (\w+)\??:`).FindAllStringSubmatch(block[1], -1) {
		fields = append(fields, m[1])
	}
	return fields
}
