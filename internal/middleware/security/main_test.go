// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"flag"
	"log/slog"
	"os"
	"testing"
)

// TestMain points the WAF audit log at a scratch directory and silences gwaf's
// rule diagnostics during benchmarks.
//
// The audit half is the one that matters. wafAuditPath builds
// config.DataDir()+"/audit/waf/<route>_audit.log", and DataDir falls back to
// "." when GATEON_DATA_DIR and GATEON_STATE_DIR are unset -- which, under `go
// test`, is the package directory. So every run of the WAF audit tests wrote
// log files into the checkout. That is invariant 3 ("no test builds into the
// checkout"), and CI fails a working tree left dirty by `go test ./...`.
//
// It had been invisible because .gitignore carries a line per package that
// does this -- /internal/middleware/audit/, /internal/router/audit/,
// /internal/server/audit/ -- so the droppings were hidden rather than stopped.
// Moving this group to a new package would have needed a sixth line. Setting
// the variable the code already reads costs one call and fixes it for good;
// the other three packages are still papered over and still worth doing.
//
// The slog half is inherited from internal/middleware's TestMain and moved
// here with the WAF benchmarks. `go test` hands the binary one stream for
// stdout and stderr and reprints all of it, so a line logged during a
// benchmark lands inside the result row:
//
//	BenchmarkWAFRequestWithInboundDLP-15   2026/09/04 INFO gwaf: a rule cannot...
//
// benchstat cannot parse that row and drops it silently, which is why
// doc/benchmarks/README.md had no WAF entries for as long as it didn't: the
// benchmarks ran green and every result was discarded before it arrived.
//
// Gated on -test.bench so `go test` keeps its logs, which are useful when a
// test fails. flag.Parse runs first because M.Run is what would otherwise
// parse them, and the flag has to be readable before that.
func TestMain(m *testing.M) {
	flag.Parse()

	dir, err := os.MkdirTemp("", "gateon-security-test")
	if err != nil {
		panic("security tests: cannot create a scratch data dir: " + err.Error())
	}
	os.Setenv("GATEON_DATA_DIR", dir)

	if f := flag.Lookup("test.bench"); f != nil && f.Value.String() != "" {
		slog.SetDefault(slog.New(slog.DiscardHandler))
	}

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
