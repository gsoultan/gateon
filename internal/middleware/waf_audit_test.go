package middleware

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureAuditLogFileCreatesDirAndFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "deep", "waf_audit.log")

	if err := ensureAuditLogFile(path); err != nil {
		t.Fatalf("ensureAuditLogFile: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected audit log file to exist: %v", err)
	}

	// Idempotent: a second call must not error or truncate.
	if err := os.WriteFile(path, []byte("existing\n"), 0o640); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if err := ensureAuditLogFile(path); err != nil {
		t.Fatalf("ensureAuditLogFile (second call): %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if string(data) != "existing\n" {
		t.Fatalf("existing audit log was truncated: %q", string(data))
	}
}

func TestResolveAuditLogPath(t *testing.T) {
	// Explicit path is returned untouched.
	if got := resolveAuditLogPath(WAFConfig{AuditLogPath: "/var/log/x.log"}); got != "/var/log/x.log" {
		t.Fatalf("explicit path: got %q", got)
	}

	// Blank path derives a default that includes a sanitized route component.
	got := resolveAuditLogPath(WAFConfig{RouteID: "api/admin route"})
	if filepath.Base(got) != "api_admin_route_audit.log" {
		t.Fatalf("default path base = %q", filepath.Base(got))
	}
}

func TestSanitizeAuditName(t *testing.T) {
	cases := map[string]string{
		"simple":        "simple",
		"with/slash":    "with_slash",
		"a b c":         "a_b_c",
		"weird*chars!":  "weird_chars",
		"gateon-global": "gateon-global",
		"__trim__":      "trim",
	}
	for in, want := range cases {
		if got := sanitizeAuditName(in); got != want {
			t.Errorf("sanitizeAuditName(%q) = %q, want %q", in, got, want)
		}
	}
}
