package main

import (
	"context"
	"os"
	"runtime"
	"sync"
	"testing"

	"github.com/gsoultan/gateon/internal/ebpf"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// ebpfCanStart reports whether reconcileEbpf would actually start the subsystem
// on this host, mirroring the supervisor's privilege/OS gate. On Linux without
// root the gate keeps eBPF disabled, so tests adjust their expectations.
func ebpfCanStart() bool {
	return !(runtime.GOOS == "linux" && os.Geteuid() != 0)
}

// fakeWAFUpdater records how many times Start was invoked and captures the
// context it received so a test can assert the loop's cancellation lifecycle.
type fakeWAFUpdater struct {
	mu      sync.Mutex
	starts  int
	lastCtx context.Context
	started chan struct{}
}

func newFakeWAFUpdater() *fakeWAFUpdater {
	return &fakeWAFUpdater{started: make(chan struct{}, 8)}
}

func (f *fakeWAFUpdater) Start(ctx context.Context) {
	f.mu.Lock()
	f.starts++
	f.lastCtx = ctx
	f.mu.Unlock()
	f.started <- struct{}{}
	<-ctx.Done() // mimic the real loop blocking until cancelled
}

func (f *fakeWAFUpdater) startCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts
}

func TestReconcileWAFAutoUpdate(t *testing.T) {
	tests := []struct {
		name            string
		enabled         bool
		preRunning      bool
		wantStartsDelta int
		wantRunning     bool
	}{
		{name: "EnableStartsLoop", enabled: true, preRunning: false, wantStartsDelta: 1, wantRunning: true},
		{name: "AlreadyRunningIsIdempotent", enabled: true, preRunning: true, wantStartsDelta: 0, wantRunning: true},
		{name: "DisableStopsLoop", enabled: false, preRunning: true, wantStartsDelta: 0, wantRunning: false},
		{name: "DisabledStaysOff", enabled: false, preRunning: false, wantStartsDelta: 0, wantRunning: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			fake := newFakeWAFUpdater()
			s := &securitySupervisor{rootCtx: ctx, wafUpdater: fake}

			if tc.preRunning {
				s.reconcileWAFAutoUpdate(&gateonv1.WafConfig{AutoUpdateRules: true})
				<-fake.started // wait until the loop goroutine has started
			}

			before := fake.startCount()
			s.reconcileWAFAutoUpdate(&gateonv1.WafConfig{AutoUpdateRules: tc.enabled})

			if tc.wantStartsDelta == 1 {
				<-fake.started
			}
			if got := fake.startCount() - before; got != tc.wantStartsDelta {
				t.Fatalf("%s: start delta = %d; want %d", tc.name, got, tc.wantStartsDelta)
			}
			if running := s.wafCancel != nil; running != tc.wantRunning {
				t.Fatalf("%s: running = %v; want %v", tc.name, running, tc.wantRunning)
			}
		})
	}
}

// TestReconcileWAFAutoUpdateNilUpdater ensures a supervisor without a WAF updater
// never panics or starts a loop even when the config enables auto-update.
func TestReconcileWAFAutoUpdateNilUpdater(t *testing.T) {
	s := &securitySupervisor{rootCtx: t.Context()}
	s.reconcileWAFAutoUpdate(&gateonv1.WafConfig{AutoUpdateRules: true})
	if s.wafCancel != nil {
		t.Fatal("nil updater must not start the auto-update loop")
	}
}

// fakeClamAV records the configs passed to Reconfigure so a test can assert how
// many times (and with what) the supervisor reconfigured ClamAV.
type fakeClamAV struct {
	mu      sync.Mutex
	calls   int
	lastCfg *gateonv1.ClamavConfig
}

func (f *fakeClamAV) Reconfigure(_ context.Context, cfg *gateonv1.ClamavConfig) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastCfg = cfg
}

func (f *fakeClamAV) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestReconcileClamAV(t *testing.T) {
	cfgA := &gateonv1.ClamavConfig{FullScanSchedule: "@daily"}
	cfgB := &gateonv1.ClamavConfig{FullScanSchedule: "@hourly"}

	t.Run("FirstApplyAlwaysReconfigures", func(t *testing.T) {
		fake := &fakeClamAV{}
		s := &securitySupervisor{rootCtx: t.Context(), clamavMgr: fake}
		s.reconcileClamAV(cfgA)
		if got := fake.callCount(); got != 1 {
			t.Fatalf("first apply: calls = %d; want 1", got)
		}
	})

	t.Run("UnchangedConfigIsIdempotent", func(t *testing.T) {
		fake := &fakeClamAV{}
		s := &securitySupervisor{rootCtx: t.Context(), clamavMgr: fake}
		s.reconcileClamAV(cfgA)
		s.reconcileClamAV(&gateonv1.ClamavConfig{FullScanSchedule: "@daily"})
		if got := fake.callCount(); got != 1 {
			t.Fatalf("unchanged: calls = %d; want 1", got)
		}
	})

	t.Run("ChangedConfigReconfigures", func(t *testing.T) {
		fake := &fakeClamAV{}
		s := &securitySupervisor{rootCtx: t.Context(), clamavMgr: fake}
		s.reconcileClamAV(cfgA)
		s.reconcileClamAV(cfgB)
		if got := fake.callCount(); got != 2 {
			t.Fatalf("changed: calls = %d; want 2", got)
		}
		if fake.lastCfg.GetFullScanSchedule() != "@hourly" {
			t.Fatalf("changed: lastCfg schedule = %q; want @hourly", fake.lastCfg.GetFullScanSchedule())
		}
	})

	t.Run("DisableReconfiguresWithNil", func(t *testing.T) {
		fake := &fakeClamAV{}
		s := &securitySupervisor{rootCtx: t.Context(), clamavMgr: fake}
		s.reconcileClamAV(cfgA)
		s.reconcileClamAV(nil)
		if got := fake.callCount(); got != 2 {
			t.Fatalf("disable: calls = %d; want 2", got)
		}
		if fake.lastCfg != nil {
			t.Fatalf("disable: lastCfg = %+v; want nil", fake.lastCfg)
		}
	})
}

// TestReconcileClamAVNilManager ensures a supervisor without a ClamAV manager
// never panics when ClamAV config is present.
func TestReconcileClamAVNilManager(t *testing.T) {
	s := &securitySupervisor{rootCtx: t.Context()}
	s.reconcileClamAV(&gateonv1.ClamavConfig{FullScanSchedule: "@daily"})
	if s.clamavApplied {
		t.Fatal("nil manager must not mark clamav as applied")
	}
}

// newEbpfSupervisor builds a supervisor wired with a fresh eBPF holder for the
// reconcileEbpf lifecycle tests.
func newEbpfSupervisor(ctx context.Context) *securitySupervisor {
	h := ebpf.NewHolder(nil)
	return &securitySupervisor{rootCtx: ctx, ebpfManager: h, ebpfHolder: h}
}

func TestReconcileEbpf(t *testing.T) {
	t.Run("EnableInstallsManagerWhenPermitted", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		s := newEbpfSupervisor(ctx)

		s.reconcileEbpf(&gateonv1.EbpfConfig{Enabled: true})

		if !s.ebpfApplied {
			t.Fatal("reconcileEbpf must mark the config as applied")
		}
		if ebpfCanStart() {
			if s.ebpfHolder.Current() == nil {
				t.Fatal("enable must install an underlying manager into the holder")
			}
			if s.ebpfCancel == nil {
				t.Fatal("enable must record a cancel func")
			}
		} else {
			if s.ebpfHolder.Current() != nil {
				t.Fatal("without privileges the holder must stay empty")
			}
		}
	})

	t.Run("UnchangedConfigIsIdempotent", func(t *testing.T) {
		if !ebpfCanStart() {
			t.Skip("privilege gate prevents eBPF from starting on this host")
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		s := newEbpfSupervisor(ctx)

		s.reconcileEbpf(&gateonv1.EbpfConfig{Enabled: true})
		first := s.ebpfHolder.Current()
		s.reconcileEbpf(&gateonv1.EbpfConfig{Enabled: true})
		if s.ebpfHolder.Current() != first {
			t.Fatal("unchanged config must not replace the underlying manager")
		}
	})

	t.Run("DisableTearsDown", func(t *testing.T) {
		if !ebpfCanStart() {
			t.Skip("privilege gate prevents eBPF from starting on this host")
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		s := newEbpfSupervisor(ctx)

		s.reconcileEbpf(&gateonv1.EbpfConfig{Enabled: true})
		s.reconcileEbpf(&gateonv1.EbpfConfig{Enabled: false})
		if s.ebpfHolder.Current() != nil {
			t.Fatal("disable must clear the underlying manager")
		}
		if s.ebpfCancel != nil {
			t.Fatal("disable must drop the cancel func")
		}
	})

	t.Run("DisabledStaysOff", func(t *testing.T) {
		s := newEbpfSupervisor(t.Context())
		s.reconcileEbpf(&gateonv1.EbpfConfig{Enabled: false})
		if s.ebpfHolder.Current() != nil {
			t.Fatal("disabled config must leave the holder empty")
		}
		if s.ebpfCancel != nil {
			t.Fatal("disabled config must not record a cancel func")
		}
	})
}

// TestReconcileEbpfNilHolder ensures a supervisor without an eBPF holder never
// panics even when the config enables eBPF.
func TestReconcileEbpfNilHolder(t *testing.T) {
	s := &securitySupervisor{rootCtx: t.Context()}
	s.reconcileEbpf(&gateonv1.EbpfConfig{Enabled: true})
	if s.ebpfApplied {
		t.Fatal("nil holder must not mark eBPF as applied")
	}
}
