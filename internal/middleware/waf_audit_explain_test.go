// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package middleware

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
)

// TestAuditRecordCarriesExplanation is the test behind the claim that an
// operator can answer "why was this blocked, and what do I do about it?" from
// the audit record alone.
//
// It drives a real block through a real gwaf engine rather than constructing a
// Decision by hand, because the thing under test is that Explain() survives the
// trip into the record — including the matched bytes, which point into a pooled
// arena and would be garbage if they were aliased rather than copied.
func TestAuditRecordCarriesExplanation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "waf_audit.log")

	a, err := newAuditLog(WAFConfig{AuditLogPath: path, RouteID: "test-route"})
	if err != nil {
		t.Fatalf("newAuditLog: %v", err)
	}
	if a == nil {
		t.Fatal("audit log is nil")
	}
	defer a.Close()

	waf, err := gwaf.New()
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("GET", "/search?q=1%27+OR+1%3D1--", "HTTP/1.1")
	tx.AddArgument("q", "1' OR 1=1--")
	d := tx.ProcessRequestHeaders()
	if !d.Blocked() {
		t.Fatalf("expected the SQL injection to be blocked, got %v", d.Reason())
	}

	req := httptest.NewRequest("GET", "/search?q=x", nil)
	a.record(d, tx.Matches(), wafObservation{routeID: "test-route", request: req})

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	line := strings.TrimSpace(string(raw))
	if line == "" {
		t.Fatal("audit log is empty")
	}

	var rec auditRecord
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatalf("audit line is not JSON: %v\n%s", err, line)
	}

	if !rec.Blocked || rec.RuleID == "" {
		t.Errorf("record does not describe a block: blocked=%v rule=%q", rec.Blocked, rec.RuleID)
	}

	// The three fields that make the record actionable rather than merely
	// informative.
	if rec.MatchedBytes == "" {
		t.Error("matched_bytes is empty: the operator cannot see what actually matched")
	}
	if len(rec.MatchedBytes) > maxMatchedBytes {
		t.Errorf("matched_bytes is %d bytes, want at most %d", len(rec.MatchedBytes), maxMatchedBytes)
	}
	if rec.MatchedAt == nil {
		t.Error("matched_at is nil: the span within the value is unknown")
	}
	if rec.Exception == nil {
		t.Fatal("suggested_exception is nil: a false positive here has no one-click fix")
	}
	if rec.Exception.RuleID == 0 {
		t.Error("suggested exception names no rule, so it would suppress nothing")
	}

	// The exception must be *narrow*. An exception with no target is a rule
	// disabled everywhere, which is the outcome this field exists to avoid.
	if rec.Exception.Target == "" {
		t.Error("suggested exception has no target: it would suppress the rule globally")
	}
}

// TestExplainCopiesMatchedBytes guards the aliasing hazard specifically. The
// explanation points into the transaction's arena, which is pooled and handed to
// the next request, so a record that aliased it would show one request's bytes
// in another request's log entry.
func TestExplainCopiesMatchedBytes(t *testing.T) {
	waf, err := gwaf.New()
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}

	var rec auditRecord
	func() {
		tx := waf.NewTransaction()
		defer tx.Close()
		tx.SetRequestLine("GET", "/s", "HTTP/1.1")
		tx.AddArgument("q", "<script>alert(1)</script>")
		d := tx.ProcessRequestHeaders()
		if !d.Blocked() {
			t.Fatalf("expected XSS to be blocked")
		}
		explain(&rec, d.Explain())
	}()
	first := rec.MatchedBytes
	if first == "" {
		t.Fatal("no matched bytes recorded")
	}

	// Recycle the arena through a different request; an aliased string would
	// change underneath the record.
	for i := 0; i < 8; i++ {
		tx := waf.NewTransaction()
		tx.SetRequestLine("GET", "/s", "HTTP/1.1")
		tx.AddArgument("q", strings.Repeat("z", 64))
		tx.ProcessRequestHeaders()
		tx.Close()
	}

	if rec.MatchedBytes != first {
		t.Errorf("matched bytes changed after the arena was reused: %q -> %q", first, rec.MatchedBytes)
	}
}
