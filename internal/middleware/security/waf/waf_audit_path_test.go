// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware/security"
)

// withDataDir points config.DataDir at a fresh directory and returns it.
func withDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("GATEON_DATA_DIR", dir)
	InvalidateWAFCache()
	t.Cleanup(InvalidateWAFCache)
	return dir
}

// TestRouteAuditLogPathIsRefusedOutsideTheAuditDirectory (ADR 0078): a route
// WAF's audit_log_path is written by anyone who may edit a middleware, and the
// WAF created the directory and appended captured request data to whatever
// file it named -- the gateway's own configuration included. A path outside
// <data-dir>/audit/waf/ is refused at save; a name inside it saves.
func TestRouteAuditLogPathIsRefusedOutsideTheAuditDirectory(t *testing.T) {
	dir := withDataDir(t)
	for _, p := range []string{
		"/var/lib/gateon/global.yaml", filepath.Join(dir, "global.yaml"), "../../x", "../waf2/x.log",
		"a/../../x.log", "/etc/cron.d/gateon", ".", filepath.Join(dir, "audit", "waf"),
	} {
		err := CheckAuditLogPathSave(map[string]string{keyAuditLogPath: p})
		if err == nil || !strings.Contains(err.Error(), "audit_log_path") || !strings.Contains(err.Error(), "audit/waf") {
			t.Errorf("audit_log_path %q: err = %v, want a refusal naming the key and the audit directory", p, err)
		}
	}
	for _, p := range []string{
		"", "myroute.log", "team-a/route.log", " spaced.log ",
		filepath.Join(dir, "audit", "waf", "api_audit.log"),
	} {
		if err := CheckAuditLogPathSave(map[string]string{keyAuditLogPath: p}); err != nil {
			t.Errorf("audit_log_path %q refused: %v", p, err)
		}
	}
}

// TestAStoredAuditLogPathOutsideTheDirectoryIsNotWrittenTo: a config saved
// before the save-time refusal keeps building -- its route keeps serving --
// but its audit log goes to the route's default file, and the file it named
// is neither created nor appended to.
func TestAStoredAuditLogPathOutsideTheDirectoryIsNotWrittenTo(t *testing.T) {
	dir := withDataDir(t)
	victim := filepath.Join(dir, "global.yaml")
	if err := os.WriteFile(victim, []byte("waf: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(t.TempDir(), "made-up", "x.log")
	for _, p := range []string{victim, "../../global.yaml", absent} {
		InvalidateWAFCache()
		mw, err := NewWAF(map[string]string{"route": "stored", keyAuditLogPath: p, "audit_log_relevant_only": "false"}, security.Deps{})
		if err != nil {
			t.Fatalf("audit_log_path %q: a stored config must keep building: %v", p, err)
		}
		h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/?id=1%27%20OR%20%271%27%3D%271", nil))
	}
	if b, _ := os.ReadFile(victim); string(b) != "waf: {}\n" {
		t.Errorf("the gateway's config was written to: %q", b)
	}
	if _, err := os.Stat(filepath.Dir(absent)); !os.IsNotExist(err) {
		t.Errorf("a directory outside the audit directory was created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "audit", "waf", "stored_audit.log")); err != nil {
		t.Errorf("the route's default audit log was not used: %v", err)
	}
}

// TestARouteAuditLogCannotEscapeThroughASymlink: a name inside the directory
// whose parent is a symlink out of it is not followed out.
func TestARouteAuditLogCannotEscapeThroughASymlink(t *testing.T) {
	dir := withDataDir(t)
	outside := t.TempDir()
	base := filepath.Join(dir, "audit", "waf")
	if err := os.MkdirAll(base, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(base, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := NewWAF(map[string]string{"route": "sym", keyAuditLogPath: "link/x.log"}, security.Deps{}); err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "x.log")); !os.IsNotExist(err) {
		t.Errorf("the audit log was created through a symlink out of the audit directory: %v", err)
	}
}

// TestARouteAuditLogNameInsideTheDirectoryIsUsed: a relative name is a file
// under <data-dir>/audit/waf/.
func TestARouteAuditLogNameInsideTheDirectoryIsUsed(t *testing.T) {
	dir := withDataDir(t)
	if _, err := NewWAF(map[string]string{"route": "named", keyAuditLogPath: "team-a/named.log"}, security.Deps{}); err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "audit", "waf", "team-a", "named.log")); err != nil {
		t.Errorf("the named audit log was not created under the audit directory: %v", err)
	}
}
