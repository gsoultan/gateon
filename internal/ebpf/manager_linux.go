//go:build linux

package ebpf

import (
	"context"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/gsoultan/gateon/internal/logger"
)

// xdpProgName is the entry-point program section name in bpf/xdp_rate_limit.c.
const xdpProgName = "xdp_gateon_main"

// mapNames are the BPF maps the Go side mutates or reads, keyed by their C
// names in bpf/xdp_rate_limit.c. They MUST match the string keys used by the
// mutation methods and GetMapStats in manager.go. We register by C name (from
// the loaded collection) rather than the generated CamelCased Go field names so
// the registry stays correct regardless of bpf2go's naming.
var mapNames = []string{
	"shunned_ips",
	"drop_stats",
	"adaptive_limits",
	"country_block_map",
	"mgmt_whitelist",
	"knocking_config",
	"lb_backends",
	"lb_backends_count",
	"ja4_blocklist",
	"cuckoo_filter",
	"global_ebpf_config",
}

// ebpfConfigVal mirrors `struct ebpf_config` in bpf/xdp_rate_limit.c. cilium/ebpf
// marshals map values by binary layout, so a local struct with matching field
// order avoids depending on the generated type name.
type ebpfConfigVal struct {
	MgmtPort            uint32
	EnableKnocking      uint32
	EnableMgmtWhitelist uint32
}

// closerFunc adapts a plain teardown function to io.Closer. Used to wrap
// *ebpf.Collection, whose Close() returns no error.
type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// Start initiates the eBPF subsystem loading on Linux.
func (m *EbpfManager) Start(ctx context.Context) {
	if m.config == nil || !m.config.Enabled {
		return
	}

	logger.L.LogInfo("Initializing eBPF performance offloading subsystem",
		"xdp_rate_limit", m.config.XdpRateLimit,
		"xdp_ip_shunning", m.config.XdpIpShunning,
		"xdp_load_balancing", m.config.XdpLoadBalancing,
		"tc_filtering", m.config.TcFiltering)

	if m.config.XdpRateLimit || m.config.XdpIpShunning || m.config.XdpLoadBalancing {
		m.loadXDP(ctx)
	}
	if m.config.TcFiltering {
		m.loadTC(ctx)
	}
}

// loadXDP loads the compiled XDP program, registers its maps so the mutation
// methods can update them, attaches it to the configured interface, pushes the
// runtime config into the kernel, and arms teardown on context cancellation.
func (m *EbpfManager) loadXDP(ctx context.Context) {
	ifaceName := "eth0"
	if m.config.Interface != "" {
		ifaceName = m.config.Interface
	}

	// setErr records why the load failed so GetMapStats can surface it (the
	// real answer to "why are the metrics zero?").
	setErr := func(err error) {
		m.mu.Lock()
		m.loadErr = err.Error()
		m.attached = false
		m.iface = ifaceName
		m.mu.Unlock()
		logger.L.LogError("eBPF XDP load failed", "interface", ifaceName, "error", err)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		setErr(fmt.Errorf("find interface %q: %w", ifaceName, err))
		return
	}

	// XDP map/program creation needs the memlock rlimit lifted on older kernels.
	if err := rlimit.RemoveMemlock(); err != nil {
		setErr(fmt.Errorf("remove memlock rlimit: %w", err))
		return
	}

	spec, err := loadGateon_ebpf()
	if err != nil {
		setErr(fmt.Errorf("load eBPF spec: %w", err))
		return
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		setErr(fmt.Errorf("create eBPF collection: %w", err))
		return
	}

	prog := coll.Programs[xdpProgName]
	if prog == nil {
		coll.Close()
		setErr(fmt.Errorf("program %q not found in collection", xdpProgName))
		return
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	if err != nil {
		coll.Close()
		setErr(fmt.Errorf("attach XDP to %s: %w", ifaceName, err))
		return
	}

	m.mu.Lock()
	for _, name := range mapNames {
		if mp := coll.Maps[name]; mp != nil {
			m.maps[name] = mp
		} else {
			logger.L.LogError("expected eBPF map missing from collection", "map", name)
		}
	}
	// Close order at teardown is reverse: link first (detaches XDP), then the
	// collection (frees programs and maps). *ebpf.Collection.Close() returns no
	// error, so wrap it to satisfy io.Closer.
	m.closers = append(m.closers, l, closerFunc(func() error {
		coll.Close()
		return nil
	}))
	m.attached = true
	m.iface = ifaceName
	m.loadErr = ""
	m.mu.Unlock()

	// Push runtime config into the kernel now that the maps exist.
	m.applyRuntimeConfig()

	logger.L.LogInfo("XDP performance offloading attached", "interface", ifaceName)

	// Detach and free on context cancellation (supervisor reconfigure / shutdown).
	go func() {
		<-ctx.Done()
		logger.L.LogInfo("Detaching XDP program", "interface", ifaceName)
		m.close()
	}()
}

// applyRuntimeConfig writes the manager's configuration into the kernel maps
// the XDP program reads at runtime (global_ebpf_config and the knock sequence).
func (m *EbpfManager) applyRuntimeConfig() {
	m.mu.RLock()
	gcfg := m.maps["global_ebpf_config"]
	m.mu.RUnlock()

	if gcfg != nil {
		val := ebpfConfigVal{MgmtPort: uint32(m.config.MgmtPort)}
		if m.config.EnableKnocking {
			val.EnableKnocking = 1
		}
		if err := gcfg.Update(uint32(0), val, ebpf.UpdateAny); err != nil {
			logger.L.LogError("failed to write global_ebpf_config", "error", err)
		}
	}

	if len(m.config.KnockingSequence) > 0 {
		if err := m.SetPortKnockingSequence(m.config.KnockingSequence); err != nil {
			logger.L.LogError("failed to seed port-knocking sequence", "error", err)
		}
	}
}

// loadTC is reserved for Traffic Control offloading, which is not yet implemented.
func (m *EbpfManager) loadTC(ctx context.Context) {
	_ = ctx
	logger.L.LogInfo("eBPF TC filtering requested but not yet implemented; skipping")
}
