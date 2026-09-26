// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build linux && !noebpf

package main

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/ebpf"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// holdsBPFCapabilities reads this process's effective capabilities directly,
// so the test does not take the gate's word for what the gate should decide.
func holdsBPFCapabilities(t *testing.T) bool {
	t.Helper()
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(status), "\n") {
		if v, ok := strings.CutPrefix(line, "CapEff:"); ok {
			eff, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			const bpf, netAdmin = 1 << 39, 1 << 12
			return err == nil && eff&bpf != 0 && eff&netAdmin != 0
		}
	}
	return false
}

// TestReconcileEbpfStartsForANonRootServiceHoldingTheCapabilities runs the real
// privilege gate, not an injected one. The gate used to require uid 0, so a
// service run as its own user with CAP_BPF and CAP_NET_ADMIN -- enough to load
// and attach both programs -- was refused. Meaningful only in that shape, which
// CI provides by running this under capsh; anywhere else it skips.
func TestReconcileEbpfStartsForANonRootServiceHoldingTheCapabilities(t *testing.T) {
	if os.Geteuid() == 0 || !holdsBPFCapabilities(t) {
		t.Skip("needs a non-root process holding CAP_BPF and CAP_NET_ADMIN")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	h := ebpf.NewHolder(nil)
	s := &securitySupervisor{rootCtx: ctx, ebpfManager: h, ebpfHolder: h}

	s.reconcileEbpf(&gateonv1.EbpfConfig{Enabled: true})

	if h.Current() == nil {
		t.Fatalf("uid %d holding CAP_BPF and CAP_NET_ADMIN was refused eBPF: the gate asked for a uid, "+
			"not for the capabilities the load needs", os.Geteuid())
	}
}
