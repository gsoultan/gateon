package handlers

import (
	"context"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func TestAnalyzeConfigNilUsesSmartEngineSummary(t *testing.T) {
	resp := analyzeConfig(context.Background(), nil)
	if !strings.Contains(resp.Summary, "Smart Engine") {
		t.Fatalf("summary should mention Smart Engine for Local Mode, got %q", resp.Summary)
	}
}

func TestAnalyzeConfigFlagsWeakPosture(t *testing.T) {
	// A bare config: WAF nil/off, no audit, etc. should surface critical findings.
	cfg := &gateonv1.GlobalConfig{
		Tls: &gateonv1.TlsConfig{Enabled: true, MinTlsVersion: "TLS1.0"},
	}
	resp := analyzeConfig(context.Background(), cfg)
	if !strings.Contains(resp.Summary, "Smart Engine") {
		t.Fatalf("summary should mention Smart Engine, got %q", resp.Summary)
	}
	if len(resp.Insights) == 0 {
		t.Fatal("expected insights for a weak configuration")
	}

	var sawWeakTLS, sawWAFDisabled bool
	for _, in := range resp.Insights {
		if strings.Contains(in.Title, "Weak minimum TLS") {
			sawWeakTLS = true
			if in.Severity != "critical" {
				t.Errorf("weak TLS should be critical, got %q", in.Severity)
			}
		}
		if strings.Contains(in.Title, "Web Application Firewall is disabled") {
			sawWAFDisabled = true
		}
	}
	if !sawWeakTLS {
		t.Error("expected a weak-TLS finding")
	}
	if !sawWAFDisabled {
		t.Error("expected a WAF-disabled finding")
	}

	// Critical findings must be ordered before info findings.
	rank := map[string]int{"critical": 0, "warning": 1, "info": 2}
	for i := 1; i < len(resp.Insights); i++ {
		if rank[resp.Insights[i-1].Severity] > rank[resp.Insights[i].Severity] {
			t.Fatalf("insights not ordered by severity: %q before %q",
				resp.Insights[i-1].Severity, resp.Insights[i].Severity)
		}
	}
}

func TestAnalyzeLogsCountsLevels(t *testing.T) {
	logs := []string{
		`time=2026-06-27T13:05:11Z level=ERROR msg="threats: scan failed" error="context deadline exceeded"`,
		`time=2026-06-27T13:05:12Z level=ERROR msg="threats: scan failed" error="context deadline exceeded"`,
		`time=2026-06-27T13:05:13Z level=WARN msg="slow query"`,
		`time=2026-06-27T13:05:14Z level=INFO msg="started"`,
	}
	out := analyzeLogs(logs)
	if !strings.Contains(out, "2 error") {
		t.Errorf("expected 2 errors in summary, got %q", out)
	}
	if !strings.Contains(out, "threats: scan failed") {
		t.Errorf("expected the most frequent message to be surfaced, got %q", out)
	}
	if !strings.Contains(out, "Local Mode") {
		t.Errorf("expected Local Mode marker, got %q", out)
	}

	if empty := analyzeLogs(nil); !strings.Contains(empty, "No logs") {
		t.Errorf("expected empty-logs message, got %q", empty)
	}
}
