package mitigation

import (
	"testing"

	"github.com/gsoultan/gateon/internal/security/correlation"
)

type fakeShun struct {
	shunned []string
	err     error
}

func (f *fakeShun) ShunIP(ip string) error {
	if f.err != nil {
		return f.err
	}
	f.shunned = append(f.shunned, ip)
	return nil
}

func newTestResponder(cfg Config, shun Shunner) (*Responder, *[]string) {
	var degraded []string
	r := New(cfg, Deps{
		Shun: shun,
		Degrade: func(fp string, _ float64, _ string) {
			degraded = append(degraded, fp)
		},
	})
	return r, &degraded
}

func TestResponder_SingleSignalTypeIsFlaggedNotMitigated(t *testing.T) {
	// A legitimate heavy client tripping ONE signal type repeatedly must never be
	// actively mitigated, regardless of severity — the core false-positive guard.
	r, degraded := newTestResponder(Config{Enabled: true, AutoShun: true}, &fakeShun{})
	got := r.Handle(correlation.Incident{
		SourceIP:    "203.0.113.7",
		Fingerprint: "fp1",
		Severity:    "critical",
		SignalTypes: []string{"rate_limit", "rate_limit", "rate_limit"},
	})
	if got != ActionFlag {
		t.Fatalf("action = %q, want %q (single distinct signal type)", got, ActionFlag)
	}
	if len(*degraded) != 0 {
		t.Errorf("expected no reputation degradation, got %v", *degraded)
	}
}

func TestResponder_AllowlistedSourceNotMitigated(t *testing.T) {
	r, degraded := newTestResponder(Config{
		Enabled:   true,
		Allowlist: ParseAllowlist("203.0.113.0/24"),
	}, &fakeShun{})
	got := r.Handle(correlation.Incident{
		SourceIP:    "203.0.113.55",
		Fingerprint: "fp1",
		Severity:    "critical",
		SignalTypes: []string{"exploit_scan", "brute_force_attempt", "sql_injection"},
	})
	if got != ActionNone {
		t.Fatalf("action = %q, want %q (allowlisted)", got, ActionNone)
	}
	if len(*degraded) != 0 {
		t.Errorf("allowlisted source must not be degraded, got %v", *degraded)
	}
}

func TestResponder_PrivateAndLoopbackNeverMitigated(t *testing.T) {
	r, _ := newTestResponder(Config{Enabled: true}, &fakeShun{})
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "192.168.0.9", "169.254.1.1"} {
		got := r.Handle(correlation.Incident{
			SourceIP:    ip,
			Severity:    "critical",
			SignalTypes: []string{"exploit_scan", "sql_injection", "brute_force_attempt"},
		})
		if got != ActionNone {
			t.Errorf("ip %s: action = %q, want %q (internal source)", ip, got, ActionNone)
		}
	}
}

func TestResponder_GraduatedTiers(t *testing.T) {
	multi := []string{"exploit_scan", "sql_injection", "brute_force_attempt"}
	tests := []struct {
		name     string
		severity string
		want     Action
	}{
		{"medium degrades", "medium", ActionDegrade},
		{"high restricts", "high", ActionRestrict},
		{"low flags", "low", ActionFlag},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := newTestResponder(Config{Enabled: true}, &fakeShun{})
			got := r.Handle(correlation.Incident{
				SourceIP:    "198.51.100.4",
				Fingerprint: "fp",
				Severity:    tc.severity,
				SignalTypes: multi,
			})
			if got != tc.want {
				t.Errorf("severity %s: action = %q, want %q", tc.severity, got, tc.want)
			}
		})
	}
}

func TestResponder_CriticalShunsWhenEnabled(t *testing.T) {
	shun := &fakeShun{}
	r, _ := newTestResponder(Config{Enabled: true, AutoShun: true}, shun)
	got := r.Handle(correlation.Incident{
		SourceIP:    "198.51.100.9",
		Fingerprint: "fp",
		Severity:    "critical",
		SignalTypes: []string{"exploit_scan", "sql_injection", "brute_force_attempt"},
	})
	if got != ActionShun {
		t.Fatalf("action = %q, want %q", got, ActionShun)
	}
	if len(shun.shunned) != 1 || shun.shunned[0] != "198.51.100.9" {
		t.Errorf("expected IP shunned, got %v", shun.shunned)
	}
}

func TestResponder_CriticalRestrictsWhenAutoShunOff(t *testing.T) {
	shun := &fakeShun{}
	r, _ := newTestResponder(Config{Enabled: true, AutoShun: false}, shun)
	got := r.Handle(correlation.Incident{
		SourceIP:    "198.51.100.9",
		Fingerprint: "fp",
		Severity:    "critical",
		SignalTypes: []string{"exploit_scan", "sql_injection", "brute_force_attempt"},
	})
	if got != ActionRestrict {
		t.Fatalf("action = %q, want %q (auto-shun off)", got, ActionRestrict)
	}
	if len(shun.shunned) != 0 {
		t.Errorf("must not shun when AutoShun is off, got %v", shun.shunned)
	}
}

func TestResponder_DisabledIsNoop(t *testing.T) {
	r, degraded := newTestResponder(Config{Enabled: false}, &fakeShun{})
	got := r.Handle(correlation.Incident{
		SourceIP:    "198.51.100.9",
		Fingerprint: "fp",
		Severity:    "critical",
		SignalTypes: []string{"exploit_scan", "sql_injection", "brute_force_attempt"},
	})
	if got != ActionNone {
		t.Fatalf("action = %q, want %q (disabled)", got, ActionNone)
	}
	if len(*degraded) != 0 {
		t.Errorf("disabled responder must not degrade, got %v", *degraded)
	}
}
