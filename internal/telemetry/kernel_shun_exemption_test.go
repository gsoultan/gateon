// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/security/mitigation"
)

// recordingKernelManager is a full ebpf.Manager that records the addresses each
// path pushed to the kernel, so a test can assert which reached the shun map and
// which the exemption held back.
type recordingKernelManager struct {
	shunned []string
}

func (m *recordingKernelManager) Start(context.Context) {}
func (m *recordingKernelManager) ShunIP(ip string) error {
	m.shunned = append(m.shunned, ip)
	return nil
}
func (m *recordingKernelManager) UnshunIP(string) error                     { return nil }
func (m *recordingKernelManager) UpdateManagementWhitelist([]string) error  { return nil }
func (m *recordingKernelManager) SetPortKnockingSequence([]int32) error     { return nil }
func (m *recordingKernelManager) UpdateLoadBalancerBackends([]string) error { return nil }
func (m *recordingKernelManager) SetAdaptiveRateLimit(string, time.Duration) error {
	return nil
}
func (m *recordingKernelManager) ClearAdaptiveRateLimit(string) error { return nil }
func (m *recordingKernelManager) GetTopIPs(int) ([]ebpf.IPStat, error) {
	return nil, nil
}
func (m *recordingKernelManager) GetMapStats() (ebpf.MapStats, error) {
	return ebpf.MapStats{}, nil
}

func (m *recordingKernelManager) pushed(ip string) bool {
	for _, got := range m.shunned {
		if got == ip {
			return true
		}
	}
	return false
}

// TestAManualBlockOfAnExemptAddressIsNotPushedToTheKernel exercises the record
// path an operator's block and the DDoS mitigation both take -- MarkIPMitigated,
// which the diagnostics ApplyRecommendation calls right after its own direct
// s.EbpfManager.ShunIP -- through the exact production chain: the telemetry
// provider is the eBPF Holder wired with the same exemption cmd/gateon installs
// (mitigation.ExemptFromEnforcement, ADR 0035).
//
// ADR 0032 left this open: MarkIPMitigated put an allowlisted address in the
// kernel's shun map even though every HTTP and TCP entrypoint serves it. The
// row is still written -- an operator's explicit block is recorded and listed --
// but the kernel must not drop below the paths that serve it.
func TestAManualBlockOfAnExemptAddressIsNotPushedToTheKernel(t *testing.T) {
	freshStore(t)
	mitigation.SetAllowlist([]netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")})
	t.Cleanup(func() { mitigation.SetAllowlist(nil) })

	rec := &recordingKernelManager{}
	holder := ebpf.NewHolder(rec)
	holder.SetExemption(mitigation.ExemptFromEnforcement)
	SetEbpfManager(holder)
	t.Cleanup(func() { globalEbpfManager.Store(&ebpfProviderContainer{}) })

	const (
		allowlisted = "203.0.113.9"
		loopback    = "127.0.0.1"
		nonExempt   = "198.51.100.7"
	)
	for _, ip := range []string{allowlisted, loopback, nonExempt} {
		if err := MarkIPMitigated(ip, "manual"); err != nil {
			t.Fatalf("MarkIPMitigated(%q) = %v", ip, err)
		}
	}

	if rec.pushed(allowlisted) {
		t.Errorf("an allowlisted address the operator blocked reached the kernel shun map")
	}
	if rec.pushed(loopback) {
		t.Errorf("a loopback address the operator blocked reached the kernel shun map")
	}
	if !rec.pushed(nonExempt) {
		t.Errorf("a non-exempt manual block did not reach the kernel shun map (got %v)", rec.shunned)
	}

	// The block is still recorded, whatever the kernel did: the allowlist exempts
	// enforcement, not the operator's record of their own decision.
	if !IsIPMitigated(nonExempt) {
		t.Errorf("a non-exempt manual block was not recorded")
	}
}
