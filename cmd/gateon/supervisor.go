package main

import (
	"context"
	"os"
	"runtime"
	"sync"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/ha"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/protobuf/proto"
)

// wafAutoUpdater is the minimal surface the supervisor needs to run the WAF
// rule auto-update loop. *middleware.WAFUpdater satisfies it; the interface
// keeps the supervisor decoupled and testable.
type wafAutoUpdater interface {
	Start(ctx context.Context)
}

// clamavReconfigurer is the minimal surface the supervisor needs to hot-reload
// the ClamAV manager. *security.ClamAVManager satisfies it (its config is held
// in an atomic pointer and Reconfigure rebuilds the scheduled jobs in place),
// which is why the manager pointer captured by the request-path server stays
// valid across reconfigurations.
type clamavReconfigurer interface {
	Reconfigure(ctx context.Context, cfg *gateonv1.ClamavConfig)
}

// securitySupervisor owns the lifecycle of the background security subsystems
// that can be reconfigured at runtime without a process restart. It subscribes
// to GlobalRegistry config changes and starts, stops, or restarts each managed
// subsystem when its configuration changes.
//
// eBPF, the WAF rule auto-update loop and the ClamAV manager are all managed
// here so they hot-reload without a process restart:
//   - eBPF is swapped in/out via an ebpf.Holder (an atomic indirection that the
//     request-path server, alerting and the metrics poll loop all reference),
//     so the underlying eBPF manager can be replaced live without invalidating
//     any captured pointer.
//   - ClamAV hot-reloads in place via Reconfigure (config held in an atomic
//     pointer), so the manager pointer the server captured stays valid.
//   - the WAF updater is an independent background loop, so toggling
//     Waf.AutoUpdateRules takes effect live.
//
// The gossip reputation sync (tied to HA) remains boot-only as it exposes no
// stop hook.
type securitySupervisor struct {
	reg         *config.GlobalRegistry
	ebpfManager ebpf.Manager
	ebpfHolder  *ebpf.Holder
	wafUpdater  wafAutoUpdater
	clamavMgr   clamavReconfigurer
	rootCtx     context.Context

	mu sync.Mutex

	anomalyCancel context.CancelFunc
	anomalyCfg    *gateonv1.AnomalyDetectionConfig

	gitops    *config.GitOpsManager
	gitopsCfg *gateonv1.GitOpsConfig

	haCancel context.CancelFunc
	haCfg    *gateonv1.HaConfig

	wafCancel context.CancelFunc

	clamavCfg     *gateonv1.ClamavConfig
	clamavApplied bool

	ebpfCancel  context.CancelFunc
	ebpfCfg     *gateonv1.EbpfConfig
	ebpfApplied bool
}

// newSecuritySupervisor builds a supervisor bound to the given config registry,
// the eBPF holder it hot-swaps (also used by the anomaly detector for
// auto-shunning), the WAF updater whose auto-update loop it manages, and the
// ClamAV manager it reconfigures on config changes (the WAF updater and ClamAV
// manager may be nil; the eBPF holder must not be nil).
func newSecuritySupervisor(rootCtx context.Context, reg *config.GlobalRegistry, ebpfHolder *ebpf.Holder, wafUpdater wafAutoUpdater, clamavMgr clamavReconfigurer) *securitySupervisor {
	return &securitySupervisor{
		reg:         reg,
		ebpfManager: ebpfHolder,
		ebpfHolder:  ebpfHolder,
		wafUpdater:  wafUpdater,
		clamavMgr:   clamavMgr,
		rootCtx:     rootCtx,
	}
}

// Run applies the current configuration once and then subscribes to future
// config changes so toggles take effect live.
func (s *securitySupervisor) Run() {
	if gc := s.reg.Get(s.rootCtx); gc != nil {
		s.reconcile(gc)
	}
	s.reg.Subscribe(func(_, newCfg *gateonv1.GlobalConfig) {
		if newCfg == nil {
			return
		}
		s.reconcile(newCfg)
	})
}

// reconcile brings every managed subsystem in line with the desired config.
func (s *securitySupervisor) reconcile(gc *gateonv1.GlobalConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reconcileAnomaly(gc.GetAnomalyDetection())
	s.reconcileGitOps(gc.GetManagement().GetGitops())
	s.reconcileHA(gc.GetHa())
	s.reconcileWAFAutoUpdate(gc.GetWaf())
	s.reconcileClamAV(gc.GetWaf().GetClamav())
	s.reconcileEbpf(gc.GetEbpf())
}

// reconcileAnomaly starts/stops/restarts the anomaly detection loop.
func (s *securitySupervisor) reconcileAnomaly(cfg *gateonv1.AnomalyDetectionConfig) {
	enabled := cfg.GetEnabled()
	running := s.anomalyCancel != nil
	if running && (!enabled || !proto.Equal(cfg, s.anomalyCfg)) {
		s.anomalyCancel()
		s.anomalyCancel = nil
		s.anomalyCfg = nil
		running = false
	}
	if !enabled || running {
		return
	}
	ad, err := telemetry.NewAnomalyDetector(cfg, s.ebpfManager)
	if err != nil {
		logger.L.LogError("failed to init anomaly detector", "error", err)
		return
	}
	ctx, cancel := context.WithCancel(s.rootCtx)
	s.anomalyCancel = cancel
	s.anomalyCfg = proto.Clone(cfg).(*gateonv1.AnomalyDetectionConfig)
	go ad.Start(ctx)
	logger.L.LogInfo("anomaly detection (re)configured", "enabled", true)
}

// reconcileGitOps starts/stops/restarts the GitOps sync loop.
func (s *securitySupervisor) reconcileGitOps(cfg *gateonv1.GitOpsConfig) {
	enabled := cfg.GetEnabled()
	running := s.gitops != nil
	if running && (!enabled || !proto.Equal(cfg, s.gitopsCfg)) {
		s.gitops.Stop()
		s.gitops = nil
		s.gitopsCfg = nil
		running = false
	}
	if !enabled || running {
		return
	}
	s.gitops = config.NewGitOpsManager(cfg, s.reg)
	s.gitopsCfg = proto.Clone(cfg).(*gateonv1.GitOpsConfig)
	s.gitops.Start(s.rootCtx)
	logger.L.LogInfo("gitops sync (re)configured", "enabled", true)
}

// reconcileHA starts/stops/restarts the HA (VIP failover) manager.
func (s *securitySupervisor) reconcileHA(cfg *gateonv1.HaConfig) {
	enabled := cfg.GetEnabled()
	running := s.haCancel != nil
	if running && (!enabled || !proto.Equal(cfg, s.haCfg)) {
		s.haCancel()
		s.haCancel = nil
		s.haCfg = nil
		running = false
	}
	if !enabled || running {
		return
	}
	manager := ha.NewHAManager(cfg)
	ctx, cancel := context.WithCancel(s.rootCtx)
	s.haCancel = cancel
	s.haCfg = proto.Clone(cfg).(*gateonv1.HaConfig)
	go manager.Start(ctx)
	logger.L.LogInfo("high availability (re)configured", "enabled", true)
}

// reconcileWAFAutoUpdate starts or stops the periodic WAF rule auto-update loop
// based on Waf.AutoUpdateRules. The loop itself re-reads the live config (URL,
// interval) on every tick, so only its on/off lifecycle needs reconciling here.
func (s *securitySupervisor) reconcileWAFAutoUpdate(cfg *gateonv1.WafConfig) {
	if s.wafUpdater == nil {
		return
	}
	enabled := cfg.GetAutoUpdateRules()
	running := s.wafCancel != nil
	if running && !enabled {
		s.wafCancel()
		s.wafCancel = nil
		running = false
	}
	if !enabled || running {
		return
	}
	ctx, cancel := context.WithCancel(s.rootCtx)
	s.wafCancel = cancel
	go s.wafUpdater.Start(ctx)
	logger.L.LogInfo("WAF rule auto-update (re)configured", "enabled", true)
}

// reconcileClamAV hot-reloads the ClamAV manager when its config changes. A nil
// cfg disables ClamAV's scheduled jobs. Reconfigure mutates the manager in
// place (atomic config swap + cron rebuild), so the server-captured pointer
// remains valid. The first reconcile always applies so boot-time state is set.
func (s *securitySupervisor) reconcileClamAV(cfg *gateonv1.ClamavConfig) {
	if s.clamavMgr == nil {
		return
	}
	if s.clamavApplied && proto.Equal(cfg, s.clamavCfg) {
		return
	}
	s.clamavMgr.Reconfigure(s.rootCtx, cfg)
	s.clamavApplied = true
	if cfg == nil {
		s.clamavCfg = nil
	} else {
		s.clamavCfg = proto.Clone(cfg).(*gateonv1.ClamavConfig)
	}
}

// reconcileEbpf starts/stops/restarts the eBPF subsystem by swapping the
// underlying manager inside the shared ebpf.Holder, so toggling Ebpf.Enabled
// (or changing its config) takes effect without a process restart. The holder
// keeps the Manager reference captured by the request path, alerting and the
// metrics poll loop valid across swaps. The first reconcile always applies so
// boot-time state is honoured.
func (s *securitySupervisor) reconcileEbpf(cfg *gateonv1.EbpfConfig) {
	if s.ebpfHolder == nil {
		return
	}
	if s.ebpfApplied && proto.Equal(cfg, s.ebpfCfg) {
		return
	}

	// Tear down any running instance before applying the new desired state.
	if s.ebpfCancel != nil {
		s.ebpfCancel()
		s.ebpfCancel = nil
		s.ebpfHolder.Swap(nil)
	}

	s.ebpfApplied = true
	s.ebpfCfg = proto.Clone(cfg).(*gateonv1.EbpfConfig)

	if !cfg.GetEnabled() {
		logger.L.LogInfo("eBPF (re)configured", "enabled", false)
		return
	}

	// eBPF needs elevated privileges (CAP_BPF/CAP_NET_ADMIN/CAP_PERFMON).
	// Degrade gracefully instead of forcing the process to run as root.
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		logger.L.LogError("eBPF is enabled but Gateon lacks sufficient privileges; " +
			"keeping it disabled. Run as root or grant CAP_BPF/CAP_NET_ADMIN/CAP_PERFMON.")
		return
	}

	ctx, cancel := context.WithCancel(s.rootCtx)
	s.ebpfCancel = cancel
	manager := ebpf.NewEbpfManager(cfg)
	s.ebpfHolder.Swap(manager)
	go manager.Start(ctx)
	go telemetry.StartEBpFPollLoop(ctx, s.ebpfHolder)
	logger.L.LogInfo("eBPF (re)configured", "enabled", true)
}
