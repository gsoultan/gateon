// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package alerting

import (
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// UseManager makes a manager with cfg and dispatchers the one HandleThreat
// reaches, for the life of t, and returns how many deliveries it has started
// and not finished. It is for the external tests, which drive a middleware
// that imports this package and so cannot live inside it.
func UseManager(t testing.TB, cfg *gateonv1.AlertingConfig, dispatchers map[string]Dispatcher) func() int32 {
	t.Helper()
	saved := manager
	m := &AlertingManager{config: cfg, dispatchers: dispatchers}
	manager = m
	t.Cleanup(func() { manager = saved })
	return m.sending.Load
}
