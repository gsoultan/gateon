// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build linux && !noebpf

package ebpf

import (
	"strings"
	"testing"
)

// These read the embedded object's spec, so they need no root and run in the
// ordinary unprivileged test run.

// TestEveryRegisteredMapIsInTheProgram: commit registers maps by name, and a
// name the program lacks is an ERROR on every attach. "ja4_blocklist" was
// registered for as long as the kernel JA4 blocklist it named had been gone,
// so every start of the gateway logged an error nobody could act on.
func TestEveryRegisteredMapIsInTheProgram(t *testing.T) {
	spec, err := loadGateon_ebpf()
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	for _, name := range mapNames {
		if _, ok := spec.Maps[name]; !ok {
			t.Errorf("mapNames registers %q, which the program does not have", name)
		}
	}
}

// TestEveryMapInTheProgramIsUsed: a map no program reads and Go never touches
// is kernel memory allocated on every load for nothing. The JA3 blocklist was
// a preallocated 10,000-entry hash that outlived the code that read it.
func TestEveryMapInTheProgramIsUsed(t *testing.T) {
	spec, err := loadGateon_ebpf()
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	used := map[string]bool{}
	for _, name := range mapNames {
		used[name] = true
	}
	for _, prog := range spec.Programs {
		for _, ins := range prog.Instructions {
			if ref := ins.Reference(); ref != "" {
				used[ref] = true
			}
		}
	}
	for name := range spec.Maps {
		if strings.HasPrefix(name, ".") {
			continue // .rodata, .data, .bss: the compiler's, not ours
		}
		if !used[name] {
			t.Errorf("map %q is in the program, but no program reads it and Go never registers it", name)
		}
	}
}
