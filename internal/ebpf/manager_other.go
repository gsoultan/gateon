//go:build !linux

package ebpf

import (
	"context"

	"github.com/gsoultan/gateon/internal/logger"
)

// Start is a no-op on non-Linux platforms: XDP/eBPF requires Linux kernel
// support. m.maps stays empty, so the mutation methods are safe no-ops and
// GetMapStats reports Attached=false. This keeps the macOS/dev build compiling
// without the generated bpf2go artifacts (which only exist on Linux).
func (m *EbpfManager) Start(ctx context.Context) {
	if m.config == nil || !m.config.Enabled {
		return
	}
	logger.L.LogInfo("eBPF offloading is enabled in config but skipped on this OS (kernel XDP support requires Linux)")

	go func() {
		<-ctx.Done()
		m.close()
	}()
}
