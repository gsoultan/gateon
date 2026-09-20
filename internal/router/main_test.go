// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import (
	"os"
	"testing"
)

// TestMain keeps the router's WAF audit logs out of the checkout.
func TestMain(m *testing.M) {
	// Point the WAF audit log at a scratch directory. wafAuditPath builds
	// config.DataDir()+"/audit/waf/<route>_audit.log", and DataDir falls back
	// to "." when GATEON_DATA_DIR and GATEON_STATE_DIR are unset -- which,
	// under `go test`, is this package's own directory. So every run wrote log
	// files into the checkout. That is invariant 3, and CI fails a working tree
	// left dirty by `go test ./...`.
	//
	// It stayed invisible because .gitignore carried a line per package that
	// does this, hiding the droppings rather than stopping them. Setting the
	// variable the code already reads costs one call.
	dir, err := os.MkdirTemp("", "gateon-router-test")
	if err != nil {
		panic("router tests: cannot create a scratch data dir: " + err.Error())
	}
	os.Setenv("GATEON_DATA_DIR", dir)

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
