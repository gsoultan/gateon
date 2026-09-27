// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package phantom is the seam between the gateway's listeners and its data
// path: what OptimizeListener puts in front of net/http, and what the
// Diagnostics page is told about the engine underneath.
//
// It used to offer two accelerations and neither survived measurement.
// GATEON_PHANTOM=1 wrapped every listener in an io_uring reactor; on two CPUs it
// was 6.7x slower per HTTP round trip, 31x slower per L4 echo, a tenth of the
// standard path's L4 throughput, and it kept 8% of a core busy while idle --
// besides ignoring deadlines and never unblocking Accept on Close, which hung
// Connection: close responses and graceful shutdown. The AF_XDP path created a
// socket and then returned an error on every call. Both are gone; the numbers
// are in the commit that removed them, and datapath_bench_test.go reproduces
// them for any engine proposed in their place.
//
// L4 sessions are not copied here. The TCP entrypoint inspects each
// connection, resolves its route and hands it to that route's l4.TCPProxy,
// which splices on Linux; ProxyL4, which this package also had, was only ever
// called with an empty target, to fail.
package phantom

import (
	"net"
	"os"
	"sync"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/pkg/l4"
)

// PhantomCore is the data-path engine behind the gateway's listeners.
type PhantomCore interface {
	// OptimizeListener returns l unchanged. Go's netpoller is the fastest
	// listener measured here; see datapath_bench_test.go.
	OptimizeListener(l net.Listener) net.Listener

	// GetStatus reports how the gateway moves L4 bytes: enabled and engine
	// "splice (zero-copy)" where plaintext TCP routes are spliced by the
	// kernel (Linux), "standard" elsewhere. splicedSessions is how many
	// sessions are being spliced right now -- the Diagnostics field it feeds
	// is still called active_phantom_ports.
	GetStatus() (enabled bool, engine string, splicedSessions int)

	// Close releases the core. It holds nothing, so it never fails.
	Close() error
}

// NewPhantomCore returns the gateway's data-path engine.
func NewPhantomCore() PhantomCore {
	noteRetiredSwitches()
	return core{}
}

// retiredSwitches are environment variables that used to select an engine
// this package no longer has.
var retiredSwitches = []string{"GATEON_PHANTOM", "GATEON_XDP_IFACE"}

// retiredNotice makes the notice below once per process, however many cores
// are built.
var retiredNotice sync.Once

// noteRetiredSwitches says, once, that a retired switch is set and does
// nothing. An operator who set GATEON_PHANTOM=1 turned something on; silently
// ignoring it would leave them believing it is still on.
func noteRetiredSwitches() {
	for _, name := range retiredSwitches {
		if v := os.Getenv(name); v != "" {
			retiredNotice.Do(func() {
				logger.L.LogWarn("GATEON_PHANTOM and GATEON_XDP_IFACE no longer change anything: "+
					"the io_uring listener measured slower than the standard path and was removed, "+
					"and the AF_XDP path never moved a byte",
					"variable", name, "value", v)
			})
			return
		}
	}
}

type core struct{}

func (core) OptimizeListener(l net.Listener) net.Listener { return l }

// spliceEngine is the engine name while L4 sessions are spliced.
const spliceEngine = "splice (zero-copy)"

func (core) GetStatus() (enabled bool, engine string, splicedSessions int) {
	if !l4.SpliceSupported() {
		return false, "standard", 0
	}
	return true, spliceEngine, int(l4.SplicedSessions())
}

func (core) Close() error { return nil }
