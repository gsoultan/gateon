// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The GitOps sync read its config with filepath.Join(tempDir, m.config.Path).
// Join cleans as it joins, so a Path of "../../etc/passwd" does not resolve
// inside tempDir — it resolves to /etc/passwd, and the read succeeded. GitOps
// settings arrive over the management API, so that promoted "may edit config"
// into "may read any file the gateway can", which is not the permission that
// was granted.
//
// Against the pre-fix code every escaping case below resolves outside the root
// and is read rather than refused.

func TestContainedPathRejectsEscapes(t *testing.T) {
	root := t.TempDir()

	escapes := []string{
		"../etc/passwd",
		"../../etc/passwd",
		"../../../../../../etc/shadow",
		"a/../../outside",
		"./../outside",
	}
	for _, rel := range escapes {
		t.Run("escape "+rel, func(t *testing.T) {
			got, err := containedPath(root, rel)
			if err == nil {
				t.Errorf("containedPath(%q, %q) = %q, want an error; the path leaves the root",
					root, rel, got)
			}
		})
	}
}

func TestContainedPathAllowsInsideRoot(t *testing.T) {
	root := t.TempDir()

	allowed := []struct{ rel, wantSuffix string }{
		{rel: "gateon.json", wantSuffix: "gateon.json"},
		{rel: "conf/gateon.json", wantSuffix: filepath.Join("conf", "gateon.json")},
		{rel: "./gateon.json", wantSuffix: "gateon.json"},
		{rel: "a/../gateon.json", wantSuffix: "gateon.json"},
		{rel: "", wantSuffix: ""},
	}
	for _, tt := range allowed {
		t.Run("allow "+tt.rel, func(t *testing.T) {
			got, err := containedPath(root, tt.rel)
			if err != nil {
				t.Fatalf("containedPath(%q, %q) errored: %v", root, tt.rel, err)
			}
			if !strings.HasPrefix(got, filepath.Clean(root)) {
				t.Errorf("result %q is not under root %q", got, root)
			}
			if tt.wantSuffix != "" && !strings.HasSuffix(got, tt.wantSuffix) {
				t.Errorf("result %q does not end in %q", got, tt.wantSuffix)
			}
		})
	}
}

// A sibling directory whose name merely starts with the root's name must not
// count as inside it. This is what the trailing separator in the check buys.
func TestContainedPathRejectsSiblingPrefix(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "gitops")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}

	// ../gitops-evil/x resolves to <base>/gitops-evil/x, which shares the
	// "<base>/gitops" prefix as a raw string but is a different directory.
	if got, err := containedPath(root, "../gitops-evil/x"); err == nil {
		t.Errorf("containedPath allowed sibling-prefix escape: %q", got)
	}
}

// The real read path: a traversing Path must fail before os.ReadFile sees it,
// even when the target exists and is readable.
func TestContainedPathGuardsARealTarget(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "clone")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(base, "secret.txt")
	if err := os.WriteFile(secret, []byte("do not read me"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := containedPath(root, "../secret.txt"); err == nil {
		t.Fatal("containedPath allowed a path to a real file outside the clone")
	}
}
