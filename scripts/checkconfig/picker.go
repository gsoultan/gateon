// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// The type picker check (truth T36 / NEW-8).
//
// The dashboard, the advisory and the posture told operators to attach a Bot
// Management or File Security middleware, and the Add Middleware picker could
// not create either: its list was a literal that had fallen ten types behind
// the factory. Every type the factory builds must be offered, and the picker
// must offer nothing the factory refuses as unknown.

const (
	factoryPath     = "internal/middleware/factory.go"
	pickerTypesPath = "ui/src/components/MiddlewareConfig/middlewareTypes.ts"
)

var (
	quotedRE      = regexp.MustCompile(`"([a-z_]+)"`)
	caseLineRE    = regexp.MustCompile(`(?m)^\s*case\s+(.+):\s*$`)
	pickerValueRE = regexp.MustCompile(`value:\s*"([a-z_]+)"`)
)

// factoryTypes reads the types Create's switch on m.Type builds.
func factoryTypes(src string) ([]string, error) {
	start := strings.Index(src, "switch m.Type {")
	if start < 0 {
		return nil, errors.New("no `switch m.Type {` in the factory")
	}
	body := src[start:]
	if end := strings.Index(body, "\tdefault:"); end >= 0 {
		body = body[:end]
	}
	var out []string
	for _, line := range caseLineRE.FindAllStringSubmatch(body, -1) {
		for _, q := range quotedRE.FindAllStringSubmatch(line[1], -1) {
			out = append(out, q[1])
		}
	}
	sort.Strings(out)
	return out, nil
}

// pickerTypes reads the values the picker offers.
func pickerTypes(src string) []string {
	var out []string
	for _, m := range pickerValueRE.FindAllStringSubmatch(src, -1) {
		out = append(out, m[1])
	}
	sort.Strings(out)
	return out
}

// comparePicker returns the factory types the picker leaves out, and the
// picker values the factory does not build.
func comparePicker(factory, picker []string) (missing, unknown []string) {
	inPicker, inFactory := map[string]bool{}, map[string]bool{}
	for _, t := range picker {
		inPicker[t] = true
	}
	for _, t := range factory {
		inFactory[t] = true
		if !inPicker[t] {
			missing = append(missing, t)
		}
	}
	for _, t := range picker {
		if !inFactory[t] {
			unknown = append(unknown, t)
		}
	}
	return missing, unknown
}

// checkPicker runs the check; true when the two lists disagree.
func checkPicker() bool {
	// #nosec G304 -- constant paths in the repository.
	fsrc, err := os.ReadFile(factoryPath)
	if err != nil {
		fatalf("reading the factory: %v", err)
	}
	// #nosec G304 -- constant paths in the repository.
	psrc, err := os.ReadFile(pickerTypesPath)
	if err != nil {
		fatalf("reading the picker's types: %v", err)
	}
	factory, err := factoryTypes(string(fsrc))
	if err != nil {
		fatalf("%v", err)
	}
	missing, unknown := comparePicker(factory, pickerTypes(string(psrc)))
	failed := reportList(missing, "middleware types the factory builds and the picker does not offer",
		fmt.Sprintf("Add each to %s, with an editor in MiddlewareConfigEditor.", pickerTypesPath))
	failed = reportList(unknown, "picker types the factory does not build", "") || failed
	if !failed {
		fmt.Printf("ok - the type picker offers every one of the %d types the factory builds\n", len(factory))
	}
	return failed
}
