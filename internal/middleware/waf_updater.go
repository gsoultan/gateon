// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package middleware

import (
	"context"
	"errors"
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
// The type remains because the API and the security-posture view report on it.
// It no longer fetches anything, and it says so rather than reporting a
// successful update that did nothing.
type WAFUpdater struct {
	globalStore config.GlobalConfigStore
	rulesPath   string
}

// ErrRuleUpdatesRetired is returned by PerformUpdate.
var ErrRuleUpdatesRetired = errors.New(
	"WAF rule updates are retired: rules are compiled into the binary, so upgrade gateon to update them")

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

// PerformUpdate reports that rule updates are retired.
//
// It returns an error rather than succeeding silently: an operator who presses
// "update rules" and is told it worked would reasonably believe their WAF
// changed.
func (u *WAFUpdater) PerformUpdate(force bool) error { return ErrRuleUpdatesRetired }
