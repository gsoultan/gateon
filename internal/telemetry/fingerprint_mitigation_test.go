package telemetry

import (
	"context"
	"testing"
)

func TestFingerprintMitigation(t *testing.T) {
	// Initialize store
	_ = InitPathStatsStore("sqlite::memory:", 1)
	defer ClosePathStatsStore(context.Background())

	ja3 := "test-ja3-fingerprint"
	ja4 := "test-ja4-fingerprint"

	// 1. Initially should not be mitigated
	if IsFingerprintMitigated(ja3, ja4) {
		t.Error("Expected fingerprint to not be mitigated initially")
	}

	// 2. Mitigate JA3
	MarkFingerprintMitigated(ja3, "JA3", "Test mitigation", "TestCategory")

	// 3. Should now be mitigated
	if !IsFingerprintMitigated(ja3, ja4) {
		t.Error("Expected JA3 to be mitigated")
	}

	// 4. Remove mitigation (Unmitigate)
	MarkFingerprintUnmitigated(ja3)

	// 5. Should immediately be unmitigated (cache test)
	if IsFingerprintMitigated(ja3, ja4) {
		t.Error("Expected JA3 to be unmitigated immediately")
	}

	// 6. Mitigate JA4
	MarkFingerprintMitigated(ja4, "JA4", "Test mitigation JA4", "TestCategory")

	// 7. Should now be mitigated
	if !IsFingerprintMitigated(ja3, ja4) {
		t.Error("Expected JA4 to be mitigated")
	}

	// 8. Test cache miss behavior
	if !IsFingerprintMitigated("", ja4) {
		t.Error("Expected JA4 to be mitigated when checked alone")
	}
}
