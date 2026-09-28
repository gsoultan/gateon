// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware/security/identity"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// A shunned address is refused before any detector sees what it sends, and
// without eBPF the refusal is IPMitigation's 403, which the Metrics middleware
// around it records. A POST refused 403 counted as a refused credential
// attempt, so a shunned address -- an office shunned by mistake whose users
// keep submitting forms -- fed the brute-force check with the shun's own
// refusals, and the moment the shun lapsed it was shunned again, twice as
// long: a renewal made of nothing the address did. The refusal is marked as
// the gateway's own (request.RefusalMitigation) and counts for neither
// detector. ADR 0031.
func TestAShunsOwnRefusalsAreNotCredentialAttempts(t *testing.T) {
	t.Setenv("GATEON_TRACE_DIR", filepath.Join(t.TempDir(), "traces"))
	_ = telemetry.ClosePathStatsStore(context.Background())
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "telemetry.db"), 1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })
	const shunned = "198.51.100.220"
	if err := telemetry.MarkIPMitigated(shunned, "test: shunned"); err != nil {
		t.Fatal(err)
	}

	chain := identity.IPMitigation()(answer200)
	code, counted := countedRefusal(chain, shunned, http.MethodPost, "/login",
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if code != http.StatusForbidden {
		t.Fatalf("the shunned address was answered %d, want the shun's 403", code)
	}
	if counted != 0 {
		t.Errorf("a POST the shun refused counted as %v refused credential attempt(s): the shun's "+
			"own refusals would renew it when it lapsed", counted)
	}
	telemetry.FlushTraces()
	traced := 0
	for _, tr := range telemetry.GetTracesFiltered(t.Context(), 100, true) {
		if tr.SourceIP != shunned {
			continue
		}
		traced++
		if tr.Refusal != "mitigation" {
			t.Errorf("the shun's refusal is traced with refusal %q, want \"mitigation\": the per-IP "+
				"detector would read it as a refused login", tr.Refusal)
		}
	}
	if traced == 0 {
		t.Error("the shun's refusal was not traced; the per-IP half of this test proves nothing")
	}
}
