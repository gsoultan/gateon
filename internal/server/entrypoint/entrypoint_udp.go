package entrypoint

import (
	"context"

	"github.com/gateon/gateon/internal/syncutil"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
)

type udpRunner struct{}

func (*udpRunner) Run(ctx context.Context, ep *gateonv1.EntryPoint, deps *Deps, wg *syncutil.WaitGroup) {
	addr := ep.Address
	if addr == "" {
		return
	}
	_, hasUDP := protocols(ep)
	if !hasUDP {
		return
	}
	startUDPServer(addr, wg, deps.ShutdownRegistry)
}
