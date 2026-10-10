// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"context"
	"time"

	"github.com/gsoultan/gateon/internal/config"
)

// WAFUpdater used to download the OWASP Core Rule Set as a zip archive, unpack
// it under the data directory, and point the engine's filesystem at it.
//
// Nothing reads those files any more. gateon's rules are compiled into the
// binary and gwaf's core ruleset ships with the engine, so the rules a build
// enforces are fixed by the build. That is the point rather than a limitation:
// a downloaded ruleset meant every install ran a slightly different WAF, the
// version depended on when the machine last had network access, and no test
// covered the combination actually running in production.
//
// The type remains because the security-posture view reports on it. It no
// longer fetches anything. It had a PerformUpdate that could only fail, behind
// a TriggerWafUpdate RPC and POST /v1/waf/update; all three are gone (ADR 0064).
type WAFUpdater struct {
	globalStore config.GlobalConfigStore
	rulesPath   string
}

// NewWAFUpdater returns an updater. The arguments are retained so callers do
// not have to change.
func NewWAFUpdater(globalStore config.GlobalConfigStore, rulesPath string) *WAFUpdater {
	return &WAFUpdater{globalStore: globalStore, rulesPath: rulesPath}
}

// LastUpdated reports when the running rules were last changed.
//
// That is the build, and gateon does not carry its own build timestamp here, so
// the zero value is returned. The dashboard renders that as "not applicable",
// which is honest; returning time.Now() would show a rule set updating every
// time somebody opened the page.
func (u *WAFUpdater) LastUpdated() time.Time { return time.Time{} }

// Start does nothing. It is kept so the server's startup sequence is unchanged.
func (u *WAFUpdater) Start(ctx context.Context) {}
