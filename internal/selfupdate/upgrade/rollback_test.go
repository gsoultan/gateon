// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package upgrade

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/selfupdate"
)

func TestPreviousOfNamesOnlyWhatTheHelperKept(t *testing.T) {
	up := Status{Phase: PhaseSucceeded, Target: "1.8.2", Previous: "1.8.1"}
	cases := map[string]struct {
		history []Status
		want    string
	}{
		"no history":                         {nil, ""},
		"the last upgrade":                   {[]Status{up}, "1.8.1"},
		"a tag with its v":                   {[]Status{{Phase: PhaseSucceeded, Target: "v1.8.2", Previous: "v1.8.1"}}, "v1.8.1"},
		"a refused install since":            {[]Status{{Phase: PhaseRefused, Target: "1.8.3", Previous: "1.8.2"}, up}, "1.8.1"},
		"a refused rollback since":           {[]Status{{Phase: PhaseRefused, Reason: ReasonNeedsRestore, Target: "1.8.2", Previous: "1.8.1"}, up}, "1.8.1"},
		"a rollback that went forward again": {[]Status{{Phase: PhaseFailed, Reason: ReasonPreviousNotReady, Target: "1.8.2", Previous: "1.8.1"}, up}, "1.8.1"},
		"left failed on this release":        {[]Status{{Phase: PhaseFailed, Reason: ReasonMigrated, Target: "1.8.2", Previous: "1.8.1"}}, "1.8.1"},
		"already rolled back by request":     {[]Status{{Phase: PhaseRolledBack, Reason: ReasonRequested, Target: "1.8.2", Previous: "1.8.1"}, up}, ""},
		"an upgrade that rolled itself back": {[]Status{{Phase: PhaseRolledBack, Target: "1.8.2", Previous: "1.8.1"}}, ""},
		"an upgrade to another release":      {[]Status{{Phase: PhaseSucceeded, Target: "1.8.3", Previous: "1.8.2"}}, ""},
		"an older upgrade to this release":   {[]Status{{Phase: PhaseSucceeded, Target: "1.9.0", Previous: "1.8.2"}, up}, ""},
		"an install still running":           {[]Status{{Phase: PhaseRestarting, Target: "1.8.2", Previous: "1.8.1"}}, ""},
		"a record naming nothing":            {[]Status{{Phase: PhaseSucceeded, Target: "1.8.2"}}, ""},
		"a reinstall of the same release":    {[]Status{{Phase: PhaseSucceeded, Target: "1.8.2", Previous: "1.8.2"}}, ""},
	}
	for name, c := range cases {
		got, ok := PreviousOf(c.history, "1.8.2")
		if got != c.want || ok != (c.want != "") {
			t.Errorf("%s: got %q (%v), want %q", name, got, ok, c.want)
		}
	}
}

// upgradedGateway is a gateway whose helper upgraded it from 1.8.1.
func upgradedGateway(t *testing.T) *gateway {
	t.Helper()
	g := newGateway(t)
	up := Status{Phase: PhaseSucceeded, Target: "1.8.2", Previous: "1.8.1", StartedAt: g.clock.Add(-48 * 60 * 60 * 1e9)}
	g.helper(up, up)
	return g
}

func (g *gateway) request() (Request, error) {
	root, err := os.OpenRoot(filepath.Join(g.opts.DataDir, SpoolName))
	if err != nil {
		return Request{}, err
	}
	defer func() { _ = root.Close() }()
	var req Request
	return req, ReadJSON(root, RequestFile, &req)
}

func (g *gateway) migrated(m Migrated) {
	g.t.Helper()
	root, err := openSpoolDir(g.opts.DataDir)
	if err != nil {
		g.t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := WriteJSON(root, MigratedFile, m, fileMode); err != nil {
		g.t.Fatal(err)
	}
}

func TestARollbackLeavesARequestNamingWhatTheHelperKept(t *testing.T) {
	g := upgradedGateway(t)
	if v := g.i.View(); v.Rollback.To != "1.8.1" || v.Rollback.NeedsRestore {
		t.Fatalf("the view offers %+v", v.Rollback)
	}
	if err := g.i.Rollback("v1.8.1", "ada\n"); err != nil {
		t.Fatal(err)
	}
	req, err := g.request()
	if err != nil {
		t.Fatalf("no request was left for the helper: %v", err)
	}
	if !req.Rollback || req.Version != "1.8.1" || req.RequestedBy != "ada" || req.Automatic {
		t.Fatalf("the request is %+v", req)
	}
	st := g.current()
	if st.Phase != PhaseRequested || st.Reason != ReasonRequested || st.Target != "1.8.2" || st.Previous != "1.8.1" {
		t.Fatalf("the view shows %+v", st)
	}
	if len(g.stager.got) != 0 || g.queued() {
		t.Fatal("a rollback downloaded a release")
	}
	if err := g.i.Rollback("1.8.1", "ada"); !errors.Is(err, ErrBusy) {
		t.Fatalf("a second rollback beside the first: %v", err)
	}
	if err := g.i.Install(testVersion, "ada", false); !errors.Is(err, ErrBusy) {
		t.Fatalf("an install beside a rollback: %v", err)
	}
	// The helper's account replaces the gateway's once it has picked it up.
	done := Status{Phase: PhaseRolledBack, Reason: ReasonRequested, Target: "1.8.2", Previous: "1.8.1", StartedAt: g.clock, FinishedAt: g.clock}
	g.helper(done, done)
	if got := g.current(); got.Phase != PhaseRolledBack {
		t.Fatalf("after the helper finished the view shows %+v", got)
	}
}

func TestARollbackIsRefusedWithoutLeavingARequest(t *testing.T) {
	cases := map[string]struct {
		arrange func(g *gateway)
		to      string
		want    error
	}{
		"another release than the one kept": {func(*gateway) {}, "1.8.0", ErrNoPrevious},
		"no release named":                  {func(*gateway) {}, "", ErrNoPrevious},
		"nothing kept":                      {func(g *gateway) { g.helper(Status{}) }, "1.8.1", ErrNoPrevious},
		"a container": {func(g *gateway) {
			g.check.st.InstallKind = selfupdate.InstallKubernetes
		}, "1.8.1", ErrBlocked},
		"the helper switched off": {func(g *gateway) {
			g.rebuild(func(o *Options) { o.HelperEnabled = func() bool { return false } })
		}, "1.8.1", ErrBlocked},
		"a migration the previous release was not tested on": {func(g *gateway) {
			g.migrated(Migrated{Version: "1.8.2", CompatibleWith: "1.8.0", Runs: []MigrationRun{{Dialect: DialectPostgres, Done: true}}})
		}, "1.8.1", ErrNeedsRestore},
		"a helper already installing": {func(g *gateway) {
			up := Status{Phase: PhaseSucceeded, Target: "1.8.2", Previous: "1.8.1"}
			g.helper(Status{Phase: PhaseInstalling, Target: testVersion, StartedAt: g.clock}, up)
		}, "1.8.1", ErrBusy},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			g := upgradedGateway(t)
			c.arrange(g)
			if err := g.i.Rollback(c.to, "ada"); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if _, err := g.request(); err == nil {
				t.Fatal("a refused rollback left a request for root")
			}
		})
	}
}

// TestTheViewSaysWhenARollbackNeedsTheHost: the dashboard must not offer a
// button the helper will refuse.
func TestTheViewSaysWhenARollbackNeedsTheHost(t *testing.T) {
	g := upgradedGateway(t)
	g.migrated(Migrated{Version: "1.8.2", CompatibleWith: "v1.8.1", Runs: []MigrationRun{{Dialect: DialectPostgres, Done: true}}})
	if v := g.i.View(); v.Rollback.To != "1.8.1" || v.Rollback.NeedsRestore {
		t.Fatalf("one release forward: %+v", v.Rollback)
	}
	g.migrated(Migrated{Version: "1.8.2", Runs: []MigrationRun{{Dialect: DialectSQLite, Database: "/d/g.db", Backup: "/d/g.db.bak", Done: true}}})
	v := g.i.View()
	if v.Rollback.To != "1.8.1" || !v.Rollback.NeedsRestore {
		t.Fatalf("a build compatible with nothing: %+v", v.Rollback)
	}
	if p := v.Proto(); p.GetRollbackVersion() != "1.8.1" || !p.GetRollbackNeedsRestore() {
		t.Fatalf("the API reports %q needs_restore=%v", p.GetRollbackVersion(), p.GetRollbackNeedsRestore())
	}
	// A record another release left decides nothing.
	g.migrated(Migrated{Version: "1.8.0", Runs: []MigrationRun{{Dialect: DialectPostgres, Done: true}}})
	if v := g.i.View(); v.Rollback.NeedsRestore {
		t.Fatal("a migration record of another release blocked the rollback")
	}
}

func TestEveryReasonOfARollbackReachesTheAPI(t *testing.T) {
	for _, r := range []Reason{ReasonRequested, ReasonNoPrevious, ReasonNeedsRestore, ReasonPreviousNotReady} {
		if !r.Requested() {
			t.Errorf("%q is not counted as a rollback's", r)
		}
		if reasonProto[r] == 0 {
			t.Errorf("%q is reported as unspecified", r)
		}
	}
	if ReasonNotReady.Requested() || ReasonMigrated.Requested() || ReasonNone.Requested() {
		t.Error("a failed upgrade's reason is counted as a rollback an operator asked for")
	}
}
