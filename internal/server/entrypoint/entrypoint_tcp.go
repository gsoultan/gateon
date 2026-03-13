package entrypoint

import (
	"context"

	"github.com/gateon/gateon/internal/syncutil"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
)

type tcpRunner struct{}

func (*tcpRunner) Run(ctx context.Context, ep *gateonv1.EntryPoint, deps *Deps, wg *syncutil.WaitGroup) {
	addr := ep.Address
	if addr == "" {
		return
	}
	hasTCP, _ := protocols(ep)
	if !hasTCP {
		return
	}
	startTCPServer(addr, ep, deps, wg, deps.ShutdownRegistry)
}
