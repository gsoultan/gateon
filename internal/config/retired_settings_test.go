// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// GitOps was removed (ADR 0098). A global.json written before that can still
// carry a management.gitops block, enabled, with a repository and a token. The
// gateway must start on it, must not act on it, and must say the block is now
// ignored rather than drop it without a word.

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

// TestAGlobalJSONWithAGitOpsBlockStillLoads: the block is skipped, the rest of
// the file is in force, and the next save writes the file without it.
func TestAGlobalJSONWithAGitOpsBlockStillLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "global.json")
	if err := os.WriteFile(path, []byte(gitopsJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := NewGlobalRegistry(path)
	if err := reg.LoadErr(); err != nil {
		t.Fatalf("a global.json with a gitops block failed to load: %v", err)
	}
	gc := reg.Get(t.Context())
	if got := gc.GetManagement().GetPort(); got != "9191" {
		t.Fatalf("management.port = %q; the rest of the file was not loaded", got)
	}
	if err := reg.Update(t.Context(), gc); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(saved)), "gitops") {
		t.Fatalf("the saved global.json still carries the gitops block:\n%s", saved)
	}
}
