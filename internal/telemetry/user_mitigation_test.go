package telemetry

import (
	"context"
	"testing"
)

func TestUserMitigation(t *testing.T) {
	// Initialize store
	_ = InitPathStatsStore("sqlite::memory:", 1)
	defer ClosePathStatsStore(context.Background())

	ja3 := "test-ja3"
	ja4 := "test-ja4"
	ja4h := "test-ja4h"

	// 1. Initially should not be mitigated
	if IsUserMitigated(ja3, ja4, ja4h) {
		t.Error("Expected user to not be mitigated initially")
	}

	// 2. Mitigate JA3
	MarkUserMitigated(ja3, "", "JA3", "Test reasoning", "TestCategory")

	// 3. Should now be mitigated
	if !IsUserMitigated(ja3, "", "") {
		t.Error("Expected JA3 to be mitigated")
	}

	// 4. Unmitigate JA3
	MarkUserUnmitigated(ja3, "")

	// 5. Should immediately be unmitigated (cache test)
	if IsUserMitigated(ja3, "", "") {
		t.Error("Expected JA3 to be unmitigated immediately")
	}

	// 6. Mitigate JA4
	MarkUserMitigated(ja4, "", "JA4", "Test reasoning JA4", "TestCategory")

	// 7. Should now be mitigated
	if !IsUserMitigated("", ja4, "") {
		t.Error("Expected JA4 to be mitigated")
	}

	// 8. Test JA4+JA4H composite
	if IsUserMitigated("", "other-ja4", "other-ja4h") {
		t.Error("Expected other JA4 combo to not be mitigated")
	}

	MarkUserMitigated(ja4, ja4h, "JA4", "Test reasoning JA4+JA4H", "TestCategory")
	if !IsUserMitigated("", ja4, ja4h) {
		t.Error("Expected JA4+JA4H to be mitigated")
	}
}

func TestIPEscalation(t *testing.T) {
	// Initialize store
	_ = InitPathStatsStore("sqlite::memory:", 1)
	defer ClosePathStatsStore(context.Background())

	ip := "1.1.1.1"

	// 1. Record 3 threats with different fingerprints from same IP
	for i := 1; i <= 3; i++ {
		st := SecurityThreat{
			SourceIP:    ip,
			Fingerprint: "user-" + string(rune('0'+i)),
			Score:       100,
			ActionTaken: "blocked",
		}
		RecordSecurityThreat(st)
	}

	// 2. Check if IP is now mitigated
	if !IsIPMitigated(ip) {
		t.Error("Expected IP to be escalated to mitigation after 3 unique malicious users")
	}
}
