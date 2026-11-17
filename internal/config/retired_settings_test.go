// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// GitOps was removed (ADR 0098). A global.json written before that can still
// carry a management.gitops block, enabled, with a repository and a token. The
// gateway must start on it, must not act on it, and must say the block is now
// ignored rather than drop it without a word. A save keeps it, so the
// previous version still has it after a rollback.

const gitopsJSON = `{
  "management": {
    "port": "9191",
    "gitops": {
      "enabled": true,
      "repository_url": "https://git.example/org/config.git",
      "branch": "main",
      "path": "global.json",
      "sync_interval_seconds": 60,
      "auth_token": "TOKEN"
    }
  }
}`

const gitopsYAML = `management:
  port: "9191"
  gitops:
    enabled: true
    repositoryurl: https://git.example/org/config.git
`

func TestRetiredKeysInNamesAGitOpsBlock(t *testing.T) {
	for name, tt := range map[string]struct {
		data   string
		isYAML bool
	}{
		"json": {gitopsJSON, false},
		"yaml": {gitopsYAML, true},
	} {
		t.Run(name, func(t *testing.T) {
			got := retiredKeysIn([]byte(tt.data), tt.isYAML)
			if !slices.Equal(got, []string{"management.gitops"}) {
				t.Fatalf("retiredKeysIn = %v; want [management.gitops]", got)
			}
		})
	}
}

func TestRetiredKeysInIgnoresACurrentConfig(t *testing.T) {
	for name, data := range map[string]string{
		"no management":     `{"waf": {"enabled": true}}`,
		"management only":   `{"management": {"port": "8080"}}`,
		"management scalar": `{"management": "odd"}`,
		"top-level gitops":  `{"gitops": {"enabled": true}}`,
		"not json":          `{`,
	} {
		t.Run(name, func(t *testing.T) {
			if got := retiredKeysIn([]byte(data), false); len(got) != 0 {
				t.Fatalf("retiredKeysIn = %v; want none", got)
			}
		})
	}
}

// TestAGlobalJSONWithAGitOpsBlockStillLoads: the block is skipped and the rest
// of the file is in force.
func TestAGlobalJSONWithAGitOpsBlockStillLoads(t *testing.T) {
	reg, _ := registryFromFile(t, "global.json", gitopsJSON)
	if err := reg.LoadErr(); err != nil {
		t.Fatalf("a global.json with a gitops block failed to load: %v", err)
	}
	if got := reg.Get(t.Context()).GetManagement().GetPort(); got != "9191" {
		t.Fatalf("management.port = %q; the rest of the file was not loaded", got)
	}
}

// TestASaveKeepsTheGitOpsBlockForARollback: every change is to be backward
// compatible with the previous version, so that an update can be rolled back.
// That version reads management.gitops. If a save from this one dropped the
// block, rolling back after any change made in the dashboard would come up
// without a setting the operator had, and nothing would say so. The block
// must come back byte-for-byte as the previous version wrote it, and the
// change that was saved must be there beside it.
func TestASaveKeepsTheGitOpsBlockForARollback(t *testing.T) {
	for name, tt := range map[string]struct{ file, data string }{
		"json": {"global.json", gitopsJSON},
		"yaml": {"global.yaml", gitopsYAML},
	} {
		t.Run(name, func(t *testing.T) {
			isYAML := name == "yaml"
			reg, path := registryFromFile(t, tt.file, tt.data)
			gc := reg.Get(t.Context())
			gc.Management.Port = "9292"
			if err := reg.Update(t.Context(), gc); err != nil {
				t.Fatal(err)
			}
			saved, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			before := retiredValuesIn([]byte(tt.data), isYAML)
			after := retiredValuesIn(saved, isYAML)
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("the saved file changed the gitops block:\n before %v\n after  %v\n%s", before, after, saved)
			}
			reloaded := NewGlobalRegistry(path)
			if got := reloaded.Get(t.Context()).GetManagement().GetPort(); got != "9292" {
				t.Fatalf("management.port after the save = %q; want the saved 9292", got)
			}
		})
	}
}

// A file that never had the block must not grow one.
func TestASaveAddsNoRetiredKeyToACurrentConfig(t *testing.T) {
	reg, path := registryFromFile(t, "global.json", `{"management": {"port": "9191"}}`)
	if err := reg.Update(t.Context(), reg.Get(t.Context())); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(saved)), "gitops") {
		t.Fatalf("a save added a gitops key to a file that had none:\n%s", saved)
	}
}

func registryFromFile(t *testing.T, name, data string) (*GlobalRegistry, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return NewGlobalRegistry(path), path
}
