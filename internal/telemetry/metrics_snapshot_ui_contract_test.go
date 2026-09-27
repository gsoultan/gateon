// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestMetricsSnapshotJSONMatchesTheDashboardTypes holds the metrics snapshot's
// JSON field names to the TypeScript types the dashboard decodes it with.
//
// Nothing generates those types: ui/src/types/metrics.ts is written by hand, and
// the snapshot reaches the dashboard over /v1/watch, whose payload the realtime
// store types as `any`. A name spelled one way here and another way there
// compiles on both sides and reads as undefined. SystemMetrics tags three fields
// "...GB" while the type said "...Gb", so every live tick replaced the status
// card's storage and memory totals with 0, and nothing noticed.
func TestMetricsSnapshotJSONMatchesTheDashboardTypes(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "ui", "src", "types", "metrics.ts"))
	if err != nil {
		t.Fatalf("read the dashboard's metrics types: %v", err)
	}
	for _, typ := range []reflect.Type{
		reflect.TypeFor[MetricsSnapshot](), reflect.TypeFor[GoldenSignals](),
		reflect.TypeFor[SystemMetrics](), reflect.TypeFor[RouteMetric](),
		reflect.TypeFor[MiddlewareMetrics](), reflect.TypeFor[LabeledCount](),
		reflect.TypeFor[TLSCertMetric](), reflect.TypeFor[TargetMetric](),
		reflect.TypeFor[DomainMetric](), reflect.TypeFor[IPMetric](),
		reflect.TypeFor[CountryMetric](), reflect.TypeFor[MitigationFunnel](),
		reflect.TypeFor[SecurityInsights](), reflect.TypeFor[IPStat](),
	} {
		t.Run(typ.Name(), func(t *testing.T) {
			wire, dashboard := jsonFieldNames(typ), tsTypeFields(t, string(src), typ.Name())
			for _, name := range wire {
				if !slices.Contains(dashboard, name) {
					t.Errorf("the gateway sends %s.%s; the dashboard's type has no such field", typ.Name(), name)
				}
			}
			for _, name := range dashboard {
				if !slices.Contains(wire, name) {
					t.Errorf("the dashboard reads %s.%s; the gateway never sends it", typ.Name(), name)
				}
			}
		})
	}
}

// jsonFieldNames lists the names encoding/json gives typ's fields.
func jsonFieldNames(typ reflect.Type) []string {
	var names []string
	for f := range typ.Fields() {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if !f.IsExported() || name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		names = append(names, name)
	}
	return names
}

// tsTypeFields lists the top-level properties of `export type <name> = {...};`
// in src: the lines indented one level inside that block.
func tsTypeFields(t *testing.T, src, name string) []string {
	t.Helper()
	block := regexp.MustCompile(`(?s)export type ` + name + ` = \{\n(.*?)\n\};`).FindStringSubmatch(src)
	if block == nil {
		t.Fatalf("ui/src/types/metrics.ts declares no type %s", name)
	}
	var fields []string
	for _, m := range regexp.MustCompile(`(?m)^  (\w+)\??:`).FindAllStringSubmatch(block[1], -1) {
		fields = append(fields, m[1])
	}
	return fields
}
