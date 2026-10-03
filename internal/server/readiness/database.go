// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package readiness

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// configDBUp is 1 while the configuration database answers and 0 while it
// does not. Before this nothing showed a Postgres outage: the data plane kept
// serving, sign-in answered 401 as if the password were wrong, and /readyz
// said ready.
var configDBUp = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "gateon_config_db_up",
	Help: "1 when the configuration (user and route) database answers a ping, 0 when it does not.",
})

// The database is pinged on this period, each ping bounded by the timeout, so
// /readyz reads a remembered answer and never waits on the database itself.
const (
	databaseCheckEvery   = 10 * time.Second
	databaseCheckTimeout = 3 * time.Second
)

// databaseDownReason is what /readyz says while the database does not answer.
// The error itself goes to the log, not to the probe, which answers anyone
// the management allowlist admits.
const databaseDownReason = "configuration database unreachable"

var database struct {
	// down is non-nil while the last ping failed.
	down atomic.Pointer[string]
}

// Pinger reports whether the configuration database answers. It returns nil
// when there is no database yet -- a first run before setup -- since there is
// nothing to be unreachable.
type Pinger func(ctx context.Context) error

// WatchDatabase pings the configuration database now and then every
// databaseCheckEvery until ctx ends, keeping the answer /readyz and the
// gateon_config_db_up gauge give.
func WatchDatabase(ctx context.Context, ping Pinger) {
	CheckDatabase(ctx, ping)
	ticker := time.NewTicker(databaseCheckEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			CheckDatabase(ctx, ping)
		}
	}
}

// CheckDatabase pings once and records the answer. A change of state is
// logged -- at ERROR when the database stops answering -- and nothing else is,
// so an outage is one line, not one every ten seconds.
func CheckDatabase(ctx context.Context, ping Pinger) {
	pctx, cancel := context.WithTimeout(ctx, databaseCheckTimeout)
	defer cancel()
	err := ping(pctx)
	if err == nil {
		configDBUp.Set(1)
		if database.down.Swap(nil) != nil {
			logger.L.LogInfo("configuration database answers again")
		}
		return
	}
	if ctx.Err() != nil {
		return // shutting down; the database did not fail
	}
	configDBUp.Set(0)
	reason := databaseDownReason
	if database.down.Swap(&reason) == nil {
		logger.L.LogError("configuration database unreachable: sign-in and configuration changes fail "+
			"until it answers; /readyz reports not ready", "error", err)
	}
}

// databaseReason is databaseDownReason while the database does not answer.
func databaseReason() string {
	if r := database.down.Load(); r != nil {
		return *r
	}
	return ""
}
