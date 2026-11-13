// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package upgrade

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/selfupdate"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// check is a release check that found what it holds.
type check struct{ st selfupdate.Status }

func (c *check) Status() selfupdate.Status { return c.st }

// stages records what it was asked to stage and answers with err.
type stages struct {
	got    []Request
	source string
	err    error
}

func (s *stages) Stage(_ context.Context, source string, req Request) error {
	s.got, s.source = append(s.got, req), source
	return s.err
}

// gateway is an installer on a host that can upgrade, with 1.8.3 offered.
type gateway struct {
	t      *testing.T
	i      *Installer
	check  *check
	stager *stages
	cfg    *gateonv1.UpdateConfig
	clock  time.Time
	opts   Options
}

func newGateway(t *testing.T) *gateway {
	t.Helper()
	g := &gateway{
		t: t, stager: &stages{}, cfg: &gateonv1.UpdateConfig{},
		// 03:00 local, inside the default window.
		clock: time.Date(2026, 11, 13, 3, 0, 0, 0, time.Local),
		check: &check{st: selfupdate.Status{
			Current: "1.8.2", ReleaseBuild: true, Latest: testVersion, UpdateAvailable: true,
			Signature: selfupdate.SignatureVerified, State: selfupdate.StateOK,
			Source: testSource, InstallKind: selfupdate.InstallSystemd,
		}},
	}
	g.opts = Options{
		Version: "1.8.2", DataDir: t.TempDir(), StateDir: t.TempDir(),
		Checker: g.check, Stager: g.stager, HasKey: true,
		Config:        func() *gateonv1.UpdateConfig { return g.cfg },
		Now:           func() time.Time { return g.clock },
		HelperEnabled: func() bool { return true },
	}
	g.i = NewInstaller(g.opts)
	return g
}

// rebuild applies a change to the options.
func (g *gateway) rebuild(change func(*Options)) {
	change(&g.opts)
	g.i = NewInstaller(g.opts)
}

// work runs the queued install, as Run would.
func (g *gateway) work() {
	g.t.Helper()
	select {
	case req := <-g.i.jobs:
		g.i.stage(context.Background(), req)
	default:
		g.t.Fatal("no install was queued")
	}
}

func (g *gateway) queued() bool { return len(g.i.jobs) > 0 }

// helper writes what the root helper would into the state directory.
func (g *gateway) helper(st Status, history ...Status) {
	g.t.Helper()
	root, err := os.OpenRoot(g.opts.StateDir)
	if err != nil {
		g.t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := WriteJSON(root, StatusFile, st, 0o644); err != nil {
		g.t.Fatal(err)
	}
	if err := WriteJSON(root, HistoryFile, history, 0o644); err != nil {
		g.t.Fatal(err)
	}
}

func (g *gateway) current() Status {
	g.t.Helper()
	v := g.i.View()
	if v.Current == nil {
		g.t.Fatal("the view shows no install")
	}
	return *v.Current
}

func TestAnInstallGoesFromDownloadToTheHelper(t *testing.T) {
	g := newGateway(t)
	if err := g.i.Install("v1.8.3", "ada", false); err != nil {
		t.Fatal(err)
	}
	if st := g.current(); st.Phase != PhaseDownloading || st.Target != testVersion || st.Previous != "1.8.2" || st.RequestedBy != "ada" {
		t.Fatalf("after Install: %+v", st)
	}
	g.work()
	if len(g.stager.got) != 1 || g.stager.got[0].Version != testVersion || g.stager.source != testSource {
		t.Fatalf("staged %+v from %q", g.stager.got, g.stager.source)
	}
	if st := g.current(); st.Phase != PhaseRequested {
		t.Fatalf("after staging: %s", st.Phase)
	}
	g.helper(Status{Phase: PhaseRestarting, Target: testVersion, Previous: "1.8.2", StartedAt: g.clock.Add(time.Second)})
	if st := g.current(); st.Phase != PhaseRestarting {
		t.Fatalf("once the helper has the request, the view still shows %s", st.Phase)
	}
}

func TestAnInstallIsRefusedOnAGatewayThatCannotInstall(t *testing.T) {
	cases := map[Blocker]func(*gateway){
		BlockerOrchestrated: func(g *gateway) { g.check.st.InstallKind = selfupdate.InstallContainer },
		BlockerDevBuild:     func(g *gateway) { g.rebuild(func(o *Options) { o.Version = "dev" }) },
		BlockerNoKey:        func(g *gateway) { g.rebuild(func(o *Options) { o.HasKey = false }) },
		BlockerNoHelper:     func(g *gateway) { g.rebuild(func(o *Options) { o.HelperEnabled = func() bool { return false } }) },
	}
	for want, arrange := range cases {
		g := newGateway(t)
		arrange(g)
		if got := g.i.Blocker(); got != want {
			t.Errorf("blocker %d, want %d", got, want)
		}
		if err := g.i.Install(testVersion, "ada", false); !errors.Is(err, ErrBlocked) {
			t.Errorf("blocker %d: Install answered %v", want, err)
		}
		if g.queued() {
			t.Errorf("blocker %d: an install was queued anyway", want)
		}
	}
}

func TestOnlyTheReleaseTheCheckVerifiedCanBeInstalled(t *testing.T) {
	cases := map[string]func(*gateway) string{
		"another version":       func(*gateway) string { return "1.8.4" },
		"not a version":         func(*gateway) string { return "latest" },
		"a list with no key":    func(g *gateway) string { g.check.st.Signature = selfupdate.SignatureNoKey; return testVersion },
		"nothing newer offered": func(g *gateway) string { g.check.st.UpdateAvailable = false; return testVersion },
	}
	for name, arrange := range cases {
		g := newGateway(t)
		if err := g.i.Install(arrange(g), "ada", false); !errors.Is(err, ErrNotOffered) {
			t.Errorf("%s: Install answered %v", name, err)
		}
		if g.queued() {
			t.Errorf("%s: an install was queued", name)
		}
	}
}

func TestASecondInstallWaitsForTheFirst(t *testing.T) {
	g := newGateway(t)
	if err := g.i.Install(testVersion, "ada", false); err != nil {
		t.Fatal(err)
	}
	if err := g.i.Install(testVersion, "grace", false); !errors.Is(err, ErrBusy) {
		t.Fatalf("while downloading: %v", err)
	}
	g.work()
	if err := g.i.Install(testVersion, "grace", false); !errors.Is(err, ErrBusy) {
		t.Fatalf("while waiting for the helper: %v", err)
	}
}

func TestAnInstallIsNotStartedWhileTheHelperIsWorking(t *testing.T) {
	g := newGateway(t)
	g.helper(Status{Phase: PhaseInstalling, Target: testVersion, StartedAt: g.clock.Add(-time.Minute)})
	if err := g.i.Install(testVersion, "ada", false); !errors.Is(err, ErrBusy) {
		t.Fatalf("got %v", err)
	}
	// A helper that died mid-install leaves its status behind for ever.
	g.helper(Status{Phase: PhaseInstalling, Target: testVersion, StartedAt: g.clock.Add(-2 * staleAfter)})
	if err := g.i.Install(testVersion, "ada", false); err != nil {
		t.Fatalf("a status left by a dead helper blocks every later install: %v", err)
	}
}

func TestAFailedDownloadIsReportedAndCanBeRetried(t *testing.T) {
	reasons := map[error]Reason{
		errors.New("connection refused"): ReasonDownload,
		selfupdate.ErrSignature:          ReasonSignature,
		ErrChecksum:                      ReasonChecksum,
		selfupdate.ErrMalformed:          ReasonMalformed,
		selfupdate.ErrNoKey:              ReasonNoKey,
	}
	for cause, want := range reasons {
		g := newGateway(t)
		g.stager.err = cause
		if err := g.i.Install(testVersion, "ada", false); err != nil {
			t.Fatal(err)
		}
		g.work()
		if st := g.current(); st.Phase != PhaseRefused || st.Reason != want || st.FinishedAt.IsZero() {
			t.Errorf("%v: got %s/%q", cause, st.Phase, st.Reason)
		}
		if err := g.i.Install(testVersion, "ada", false); err != nil {
			t.Errorf("%v: a retry by hand was refused: %v", cause, err)
		}
	}
}

func TestARequestTheHelperNeverTakesIsWithdrawn(t *testing.T) {
	g := newGateway(t)
	spool := filepath.Join(g.opts.DataDir, SpoolName)
	if err := os.MkdirAll(spool, spoolMode); err != nil {
		t.Fatal(err)
	}
	request := filepath.Join(spool, RequestFile)
	if err := os.WriteFile(request, []byte("{}"), fileMode); err != nil {
		t.Fatal(err)
	}
	if err := g.i.Install(testVersion, "ada", false); err != nil {
		t.Fatal(err)
	}
	g.work()
	g.clock = g.clock.Add(helperGrace - time.Second)
	if st := g.current(); st.Phase != PhaseRequested {
		t.Fatalf("within the grace period: %s", st.Phase)
	}
	g.clock = g.clock.Add(2 * time.Second)
	if st := g.current(); st.Phase != PhaseRefused || st.Reason != ReasonHelper {
		t.Fatalf("after the grace period: %s/%q", st.Phase, st.Reason)
	}
	if _, err := os.Stat(request); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the request was left to be installed whenever the helper is next enabled")
	}
}

func TestTheViewShowsTheHelpersLastOutcomeAndHistory(t *testing.T) {
	g := newGateway(t)
	if v := g.i.View(); v.Current != nil || len(v.History) != 0 {
		t.Fatalf("a gateway never upgraded shows %+v", v)
	}
	done := Status{Phase: PhaseRolledBack, Reason: ReasonNotReady, Target: testVersion, Previous: "1.8.2"}
	g.helper(done, done, Status{Phase: PhaseSucceeded, Target: "1.8.2", Previous: "1.8.1"})
	v := g.i.View()
	if v.Current == nil || v.Current.Phase != PhaseRolledBack || len(v.History) != 2 {
		t.Fatalf("got %+v", v)
	}
}

// automatic switches automatic installs on and evaluates the policy once.
func (g *gateway) automatic() bool {
	g.cfg.AutoInstall = true
	g.i.auto()
	return g.queued()
}

func TestAnAutomaticInstallStartsInsideTheWindow(t *testing.T) {
	g := newGateway(t)
	if !g.automatic() {
		t.Fatal("a patch release inside the window was not installed")
	}
	if st := g.current(); !st.Automatic || st.RequestedBy != "" {
		t.Fatalf("got %+v", st)
	}
}

func TestNothingInstallsItselfUnlessSwitchedOn(t *testing.T) {
	g := newGateway(t)
	g.i.auto()
	if g.queued() {
		t.Fatal("a release was installed with automatic install off")
	}
}

func TestAnAutomaticInstallHoldsToItsPolicy(t *testing.T) {
	cases := map[string]func(*gateway){
		"outside the window":      func(g *gateway) { g.clock = g.clock.Add(6 * time.Hour) },
		"a minor release":         func(g *gateway) { g.check.st.Latest = "1.9.0" },
		"an unverified list":      func(g *gateway) { g.check.st.Signature = selfupdate.SignatureNoKey },
		"nothing newer":           func(g *gateway) { g.check.st.UpdateAvailable = false },
		"a container":             func(g *gateway) { g.check.st.InstallKind = selfupdate.InstallContainer },
		"switched off by the env": func(g *gateway) { g.t.Setenv(EnvAutoInstall, "0") },
		"rolled back before": func(g *gateway) {
			failed := Status{Phase: PhaseRolledBack, Reason: ReasonNotReady, Target: testVersion}
			g.helper(failed, failed)
		},
	}
	for name, arrange := range cases {
		t.Run(name, func(t *testing.T) {
			g := newGateway(t)
			arrange(g)
			if g.automatic() {
				t.Fatal("the release was installed")
			}
		})
	}
}

func TestAWiderScopeLetsAMinorReleaseInstallItself(t *testing.T) {
	g := newGateway(t)
	g.check.st.Latest = "1.9.0"
	g.cfg.AutoInstallScope = gateonv1.UpdateScope_UPDATE_SCOPE_MINOR
	if !g.automatic() {
		t.Fatal("scope minor did not allow 1.8.2 to 1.9.0")
	}
}

func TestAnAutomaticInstallThatCouldNotDownloadIsSpaced(t *testing.T) {
	g := newGateway(t)
	g.stager.err = errors.New("connection refused")
	if !g.automatic() {
		t.Fatal("the first attempt did not start")
	}
	g.work()
	g.clock = g.clock.Add(autoEvery)
	if g.automatic() {
		t.Fatal("the source was asked again five minutes after it failed")
	}
	g.clock = g.clock.Add(24 * time.Hour)
	if !g.automatic() {
		t.Fatal("the install was never tried again")
	}
}
