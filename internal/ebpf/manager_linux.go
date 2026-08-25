// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build linux && !noebpf

package ebpf

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/gsoultan/gateon/internal/logger"
)

// Entry-point program names in bpf/xdp_rate_limit.c.
const (
	xdpProgName = "xdp_gateon_main"
	tcProgName  = "tc_gateon_ingress"
)

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
	"xsk_map",
	"phantom_ports",
	"global_ebpf_config",
	"ip_telemetry",
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
//
// XDP and TC are alternatives, not layers. Both hooks read the same maps and
// make the same drop decisions, and XDP sits strictly earlier in the stack, so
// running both would mean TC re-checking only the packets XDP already passed.
// TC is therefore loaded when XDP is not wanted, or when XDP was wanted and
// could not attach — which is exactly the EC2 case the diagnosis points at.
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
		if m.isAttached() {
			if m.config.TcFiltering {
				logger.L.LogInfo("tc_filtering ignored: XDP is attached and filters strictly earlier",
					"interface", m.ifaceName())
			}
			return
		}
		if m.config.TcFiltering {
			logger.L.LogInfo("XDP did not attach; falling back to the TC ingress hook as configured",
				"interface", m.ifaceName())
		}
	}

	if m.config.TcFiltering {
		m.loadTC(ctx)
		if gaps := tcUnsupported(m.config); m.isAttached() && len(gaps) > 0 {
			logger.L.LogWarn("TC ingress cannot enforce every configured eBPF feature; "+
				"these are NOT in force on this hook and need native XDP",
				"interface", m.ifaceName(), "unenforced", gaps)
		}
	}
}

// isAttached reports whether a hook is currently attached.
func (m *EbpfManager) isAttached() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.attached
}

// ifaceName is the configured interface, defaulting to eth0. Note that modern
// EC2 AMIs name the primary interface ens5 or enX0, so the default is only
// right inside a container netns.
func (m *EbpfManager) ifaceName() string {
	if m.config != nil && m.config.Interface != "" {
		return m.config.Interface
	}
	return "eth0"
}

// hookSpec describes one attachable program. XDP and TC differ only in which
// program they pull from the collection and how they attach it, so they share
// the load path rather than duplicating the collection lifecycle — two
// collections would mean two independent sets of maps, and the Go-side mutators
// would silently only reach one of them.
type hookSpec struct {
	progName string
	label    string
	attach   func(prog *ebpf.Program, iface *net.Interface) (io.Closer, string, error)
}

// loadXDP loads and attaches the XDP program.
func (m *EbpfManager) loadXDP(ctx context.Context) {
	m.loadHook(ctx, hookSpec{
		progName: xdpProgName,
		label:    "XDP",
		attach: func(prog *ebpf.Program, iface *net.Interface) (io.Closer, string, error) {
			l, mode, err := attachXDP(prog, iface, allowGenericXDP(m.config))
			if err != nil {
				return nil, "", err
			}
			return l, mode, nil
		},
	})
}

// loadTC loads and attaches the TC (clsact ingress) program.
func (m *EbpfManager) loadTC(ctx context.Context) {
	m.loadHook(ctx, hookSpec{
		progName: tcProgName,
		label:    "TC",
		attach: func(prog *ebpf.Program, iface *net.Interface) (io.Closer, string, error) {
			return attachTC(prog, iface)
		},
	})
}

// loadHook loads the compiled object, resolves the hook's program, attaches it
// to the configured interface, and hands off to commit for map registration and
// teardown wiring.
func (m *EbpfManager) loadHook(ctx context.Context, h hookSpec) {
	ifaceName := m.ifaceName()

	// setErr records why the load failed so GetMapStats can surface it (the
	// real answer to "why are the metrics zero?").
	setErr := func(err error) {
		m.mu.Lock()
		m.loadErr = err.Error()
		m.attached = false
		m.iface = ifaceName
		m.attachMode = ""
		m.mu.Unlock()
		logger.L.LogError("eBPF load failed", "hook", h.label, "interface", ifaceName, "error", err)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		setErr(fmt.Errorf("find interface %q: %w", ifaceName, err))
		return
	}

	// Map/program creation needs the memlock rlimit lifted on older kernels.
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

	prog := coll.Programs[h.progName]
	if prog == nil {
		coll.Close()
		setErr(fmt.Errorf("program %q not found in collection", h.progName))
		return
	}

	l, mode, err := h.attach(prog, iface)
	if err != nil {
		coll.Close()
		setErr(fmt.Errorf("attach %s to %s: %w", h.label, ifaceName, err))
		return
	}

	m.commit(ctx, coll, l, ifaceName, mode, h.label)
}

// commit registers the collection's maps, records attach state, pushes runtime
// config into the kernel, and arms teardown on context cancellation.
func (m *EbpfManager) commit(ctx context.Context, coll *ebpf.Collection, l io.Closer, ifaceName, mode, label string) {
	m.mu.Lock()
	for _, name := range mapNames {
		if mp := coll.Maps[name]; mp != nil {
			m.maps[name] = mp
		} else {
			logger.L.LogError("expected eBPF map missing from collection", "map", name)
		}
	}
	// Close order at teardown is reverse: link first (detaches the program),
	// then the collection (frees programs and maps). *ebpf.Collection.Close()
	// returns no error, so wrap it to satisfy io.Closer.
	m.closers = append(m.closers, l, closerFunc(func() error {
		coll.Close()
		return nil
	}))
	m.attached = true
	m.iface = ifaceName
	m.loadErr = ""
	m.attachMode = mode
	m.mu.Unlock()

	// Push runtime config into the kernel now that the maps exist.
	m.applyRuntimeConfig()

	if mode == attachModeGeneric {
		logger.L.LogWarn("XDP attached in generic (SKB) mode by explicit opt-in; every packet now pays the "+
			"program cost without being dropped any earlier — prefer tc_filtering on this NIC",
			"interface", ifaceName)
	} else {
		logger.L.LogInfo("eBPF offloading attached", "hook", label, "interface", ifaceName, "mode", mode)
	}

	// Detach and free on context cancellation (supervisor reconfigure / shutdown).
	go func() {
		<-ctx.Done()
		logger.L.LogInfo("Detaching eBPF program", "hook", label, "interface", ifaceName)
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
