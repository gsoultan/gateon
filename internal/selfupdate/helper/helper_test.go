// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package helper

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/selfupdate"
	"github.com/gsoultan/gateon/internal/selfupdate/upgrade"
)

const (
	installed = "1.8.2"
	offered   = "1.8.3"
	testArch  = "amd64"
)

// fakeELF is the smallest file debug/elf opens: a 64-bit header for machine
// and nothing else, followed by tag so two binaries differ.
func fakeELF(t *testing.T, machine elf.Machine, tag string) []byte {
	t.Helper()
	var buf bytes.Buffer
	hdr := elf.Header64{
		Ident:   [elf.EI_NIDENT]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)},
		Type:    uint16(elf.ET_EXEC),
		Machine: uint16(machine),
		Version: uint32(elf.EV_CURRENT),
		Ehsize:  64,
	}
	if err := binary.Write(&buf, binary.LittleEndian, hdr); err != nil {
		t.Fatal(err)
	}
	buf.WriteString(tag)
	return buf.Bytes()
}

// archive builds a release archive as goreleaser lays it out.
func archive(t *testing.T, version string, bin []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	dir := "gateon_" + version + "_linux_" + testArch + "/"
	for name, body := range map[string][]byte{dir + "LICENSE": []byte("MIT"), dir + "gateon": bin} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// service is a gateway service that does what onStart says when started.
type service struct {
	stops, starts int
	restarts      int
	onStart       func(starts int)
}

// Restart is the one operation the helper has: the old process stops and the
// next one starts with no moment in between where the helper acts.
func (s *service) Restart(context.Context) error {
	s.stops++
	s.starts++
	if s.onStart != nil {
		s.onStart(s.starts)
	}
	return nil
}
func (s *service) Restarts(context.Context) int { return s.restarts }

// host is a machine with a gateway installed and a release in its spool.
type host struct {
	t       *testing.T
	cfg     Config
	svc     *service
	key     ed25519.PrivateKey
	oldBin  []byte
	newBin  []byte
	clock   time.Time
	slept   time.Duration
	archive string
}

func newHost(t *testing.T) *host {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	h := &host{
		t: t, svc: &service{}, key: key,
		oldBin:  fakeELF(t, elf.EM_X86_64, "old"),
		newBin:  fakeELF(t, elf.EM_X86_64, "new"),
		clock:   time.Date(2026, 11, 13, 2, 0, 0, 0, time.UTC),
		archive: "gateon_" + offered + "_linux_" + testArch + ".tar.gz",
	}
	h.cfg = Config{
		Version:    installed,
		BinaryPath: filepath.Join(dir, "bin", "gateon"),
		DataDir:    filepath.Join(dir, "data"),
		StateDir:   filepath.Join(dir, "state"),
		Keys:       []ed25519.PublicKey{pub},
		Service:    h.svc,
		Arch:       testArch,
		Now:        func() time.Time { return h.clock },
		Sleep:      func(_ context.Context, d time.Duration) { h.clock = h.clock.Add(d); h.slept += d },
		Logf:       t.Logf,
	}
	for _, d := range []string{filepath.Dir(h.cfg.BinaryPath), filepath.Join(h.cfg.DataDir, upgrade.SpoolName)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	h.write(h.cfg.BinaryPath, h.oldBin)
	h.release(offered, archive(t, offered, h.newBin))
	h.request(offered)
	return h
}

func (h *host) write(path string, data []byte) {
	h.t.Helper()
	if err := os.WriteFile(path, data, 0o755); err != nil {
		h.t.Fatal(err)
	}
}

func (h *host) spool(name string) string {
	return filepath.Join(h.cfg.DataDir, upgrade.SpoolName, name)
}

// release puts a signed release of version, holding tarball, in the spool.
func (h *host) release(version string, tarball []byte) {
	h.t.Helper()
	sum := sha256.Sum256(tarball)
	name := "gateon_" + version + "_linux_" + testArch + ".tar.gz"
	sums := []byte(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	h.write(h.spool(name), tarball)
	h.write(h.spool(upgrade.ChecksumsFile), sums)
	h.write(h.spool(upgrade.SignatureFile), selfupdate.Sign(h.key, sums))
}

func (h *host) request(version string) {
	h.t.Helper()
	h.json(h.spool(upgrade.RequestFile), upgrade.Request{Version: version, RequestedBy: "ada", RequestedAt: h.clock})
}

func (h *host) json(path string, v any) {
	h.t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		h.t.Fatal(err)
	}
	h.write(path, data)
}

// answer makes the started gateway report ready, as the real one does: by
// writing back the nonce the helper left in its status.
func (h *host) answer() {
	h.t.Helper()
	var st upgrade.Status
	data, err := os.ReadFile(filepath.Join(h.cfg.StateDir, upgrade.StatusFile))
	if err != nil {
		h.t.Fatal(err)
	}
	if err := json.Unmarshal(data, &st); err != nil {
		h.t.Fatal(err)
	}
	h.json(h.spool(upgrade.ReadyFile), upgrade.Ready{Version: st.Expect, Nonce: st.Nonce})
}

func (h *host) run() upgrade.Status {
	h.t.Helper()
	st, err := Run(context.Background(), h.cfg)
	if err != nil {
		h.t.Fatalf("Run: %v", err)
	}
	return st
}

func (h *host) installedBinary() string {
	h.t.Helper()
	data, err := os.ReadFile(h.cfg.BinaryPath)
	if err != nil {
		h.t.Fatal(err)
	}
	switch {
	case bytes.Equal(data, h.oldBin):
		return "old"
	case bytes.Equal(data, h.newBin):
		return "new"
	}
	return "neither"
}

// refused asserts an install that touched nothing.
func (h *host) refused(st upgrade.Status, reason upgrade.Reason) {
	h.t.Helper()
	if st.Phase != upgrade.PhaseRefused || st.Reason != reason {
		h.t.Fatalf("got %s/%q, want refused/%q", st.Phase, st.Reason, reason)
	}
	if got := h.installedBinary(); got != "old" {
		h.t.Fatalf("a refused release left the %s binary installed", got)
	}
	if h.svc.stops != 0 || h.svc.starts != 0 {
		h.t.Fatalf("a refused release stopped the gateway %d times and started it %d", h.svc.stops, h.svc.starts)
	}
	if _, err := os.Stat(h.cfg.BinaryPath + stagedSuffix); !errors.Is(err, os.ErrNotExist) {
		h.t.Fatalf("a refused release left a staged binary behind: %v", err)
	}
}

func TestAVerifiedReleaseIsInstalledAndTheOldBinaryKept(t *testing.T) {
	h := newHost(t)
	h.svc.onStart = func(int) { h.answer() }
	st := h.run()
	if st.Phase != upgrade.PhaseSucceeded || st.Target != offered || st.Previous != installed {
		t.Fatalf("got %+v", st)
	}
	if got := h.installedBinary(); got != "new" {
		t.Fatalf("the %s binary is installed", got)
	}
	kept, err := os.ReadFile(filepath.Join(h.cfg.StateDir, previousFile))
	if err != nil || !bytes.Equal(kept, h.oldBin) {
		t.Fatalf("the replaced binary was not kept: %v", err)
	}
	if h.svc.stops != 1 || h.svc.starts != 1 {
		t.Fatalf("stopped %d times, started %d", h.svc.stops, h.svc.starts)
	}
	for _, name := range []string{upgrade.RequestFile, h.archive, upgrade.ChecksumsFile, upgrade.ReadyFile} {
		if _, err := os.Stat(h.spool(name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s is still in the spool", name)
		}
	}
	var history []upgrade.Status
	data, _ := os.ReadFile(filepath.Join(h.cfg.StateDir, upgrade.HistoryFile))
	if err := json.Unmarshal(data, &history); err != nil || len(history) != 1 || history[0].RequestedBy != "ada" {
		t.Fatalf("history: %v %+v", err, history)
	}
	if st.Nonce != "" || history[0].Nonce != "" {
		t.Fatal("a finished status still carries its nonce")
	}
}

// TestTheGatewayIsRestartedOnceWithTheNewBinaryAlreadyInPlace: the service
// manager keeps the listening sockets open across a restart and closes them
// when the service is stopped (ADR 0088). A helper that stopped the gateway,
// swapped the binary and started it would close every listener in between.
func TestTheGatewayIsRestartedOnceWithTheNewBinaryAlreadyInPlace(t *testing.T) {
	h := newHost(t)
	var runningAtRestart []string
	h.svc.onStart = func(int) {
		runningAtRestart = append(runningAtRestart, h.installedBinary())
		h.answer()
	}
	if st := h.run(); st.Phase != upgrade.PhaseSucceeded {
		t.Fatalf("got %+v", st)
	}
	if len(runningAtRestart) != 1 || runningAtRestart[0] != "new" {
		t.Fatalf("the gateway was restarted onto %v, want one restart onto the new binary", runningAtRestart)
	}

	back := newHost(t)
	runningAtRestart = nil
	back.svc.onStart = func(starts int) {
		runningAtRestart = append(runningAtRestart, back.installedBinary())
		if starts == 2 {
			back.answer()
		}
	}
	if st := back.run(); st.Phase != upgrade.PhaseRolledBack {
		t.Fatalf("got %+v", st)
	}
	if len(runningAtRestart) != 2 || runningAtRestart[1] != "old" {
		t.Fatalf("the rollback restarted onto %v, want a second restart onto the old binary", runningAtRestart)
	}
}

func TestAnArchiveThatIsNotTheSignedOneIsRefused(t *testing.T) {
	h := newHost(t)
	// The list and its signature are genuine; the archive beside them is not.
	h.write(h.spool(h.archive), archive(t, offered, fakeELF(t, elf.EM_X86_64, "planted")))
	h.refused(h.run(), upgrade.ReasonChecksum)
}

func TestAListSignedByAnotherKeyIsRefused(t *testing.T) {
	h := newHost(t)
	_, other, _ := ed25519.GenerateKey(nil)
	sums, _ := os.ReadFile(h.spool(upgrade.ChecksumsFile))
	h.write(h.spool(upgrade.SignatureFile), selfupdate.Sign(other, sums))
	h.refused(h.run(), upgrade.ReasonSignature)
}

func TestAnUnsignedListIsRefused(t *testing.T) {
	h := newHost(t)
	if err := os.Remove(h.spool(upgrade.SignatureFile)); err != nil {
		t.Fatal(err)
	}
	h.refused(h.run(), upgrade.ReasonSignature)
}

func TestABuildWithNoReleaseKeyInstallsNothing(t *testing.T) {
	h := newHost(t)
	h.cfg.Keys = nil
	h.refused(h.run(), upgrade.ReasonNoKey)
}

func TestARequestCannotInstallAnOlderOrEqualRelease(t *testing.T) {
	for _, version := range []string{"1.8.1", installed} {
		h := newHost(t)
		h.release(version, archive(t, version, h.newBin))
		h.request(version)
		h.refused(h.run(), upgrade.ReasonNotNewer)
	}
}

func TestARequestCannotInstallOverADevelopmentBuild(t *testing.T) {
	h := newHost(t)
	h.cfg.Version = "dev"
	h.refused(h.run(), upgrade.ReasonNotNewer)
}

func TestAnOperatorAtARootShellMayDowngrade(t *testing.T) {
	h := newHost(t)
	h.release("1.8.1", archive(t, "1.8.1", h.newBin))
	h.request("1.8.1")
	h.cfg.AllowDowngrade = true
	h.svc.onStart = func(int) { h.answer() }
	if st := h.run(); st.Phase != upgrade.PhaseSucceeded || h.installedBinary() != "new" {
		t.Fatalf("got %+v with the %s binary", st, h.installedBinary())
	}
}

func TestARequestNamingAnotherVersionThanTheSignedListIsRefused(t *testing.T) {
	h := newHost(t)
	h.request("1.9.0")
	h.refused(h.run(), upgrade.ReasonMalformed)
}

func TestABinaryForAnotherMachineIsRefusedBeforeTheSwap(t *testing.T) {
	h := newHost(t)
	h.release(offered, archive(t, offered, fakeELF(t, elf.EM_AARCH64, "arm")))
	h.refused(h.run(), upgrade.ReasonMalformed)
}

func TestAFileThatIsNotAnExecutableIsRefusedBeforeTheSwap(t *testing.T) {
	h := newHost(t)
	h.release(offered, archive(t, offered, []byte("#!/bin/sh\necho not a gateway\n")))
	h.refused(h.run(), upgrade.ReasonMalformed)
}

func TestASymlinkInTheSpoolIsNotFollowedOutOfIt(t *testing.T) {
	h := newHost(t)
	outside := filepath.Join(t.TempDir(), "secret.tar.gz")
	tarball, _ := os.ReadFile(h.spool(h.archive))
	h.write(outside, tarball)
	if err := os.Remove(h.spool(h.archive)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, h.spool(h.archive)); err != nil {
		t.Fatal(err)
	}
	// The bytes behind the link are the genuine archive, so only the refusal
	// to follow it can explain a refusal here.
	h.refused(h.run(), upgrade.ReasonChecksum)
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("the file the link named was touched: %v", err)
	}
}

func TestARequestThatIsASymlinkIsRemovedWithoutTouchingItsTarget(t *testing.T) {
	h := newHost(t)
	outside := filepath.Join(t.TempDir(), "request.json")
	h.json(outside, upgrade.Request{Version: offered})
	if err := os.Remove(h.spool(upgrade.RequestFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, h.spool(upgrade.RequestFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), h.cfg); err == nil {
		t.Fatal("a request reached through a symlink out of the data directory was accepted")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("the link's target was removed: %v", err)
	}
	if _, err := os.Lstat(h.spool(upgrade.RequestFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the link was left in place to trigger the helper again")
	}
	if got := h.installedBinary(); got != "old" {
		t.Fatalf("the %s binary is installed", got)
	}
}

func TestNoRequestIsNotAnInstall(t *testing.T) {
	h := newHost(t)
	if err := os.Remove(h.spool(upgrade.RequestFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), h.cfg); !errors.Is(err, ErrNoRequest) {
		t.Fatalf("got %v", err)
	}
}

func TestAGatewayThatNeverReportsReadyIsRolledBack(t *testing.T) {
	h := newHost(t)
	// The new gateway says nothing; the old one, put back, answers.
	h.svc.onStart = func(starts int) {
		if starts == 2 {
			h.answer()
		}
	}
	st := h.run()
	if st.Phase != upgrade.PhaseRolledBack || st.Reason != upgrade.ReasonNotReady {
		t.Fatalf("got %s/%q", st.Phase, st.Reason)
	}
	if got := h.installedBinary(); got != "old" {
		t.Fatalf("the %s binary is installed after a rollback", got)
	}
	if h.svc.stops != 2 || h.svc.starts != 2 {
		t.Fatalf("stopped %d times, started %d", h.svc.stops, h.svc.starts)
	}
	if h.slept < DefaultReadyTimeout || h.slept > DefaultReadyTimeout+time.Second {
		t.Fatalf("waited %s for the new gateway, want the timeout of %s", h.slept, DefaultReadyTimeout)
	}
	if st.RestoreDatabase {
		t.Fatal("a database restore was ordered though nothing migrated")
	}
}

func TestAReadyAnswerWithoutTheNonceIsNotBelieved(t *testing.T) {
	h := newHost(t)
	h.svc.onStart = func(starts int) {
		if starts == 1 {
			// What a gateway could have planted before it was stopped.
			h.json(h.spool(upgrade.ReadyFile), upgrade.Ready{Version: offered, Nonce: "guessed"})
			return
		}
		h.answer()
	}
	if st := h.run(); st.Phase != upgrade.PhaseRolledBack {
		t.Fatalf("got %s: a ready answer with the wrong nonce was accepted", st.Phase)
	}
}

func TestACrashLoopingGatewayIsRolledBackWithoutWaitingOutTheTimeout(t *testing.T) {
	h := newHost(t)
	h.svc.onStart = func(starts int) {
		if starts == 1 {
			h.svc.restarts = crashLoopRestarts
			return
		}
		h.svc.restarts = 0
		h.answer()
	}
	if st := h.run(); st.Phase != upgrade.PhaseRolledBack {
		t.Fatalf("got %s", st.Phase)
	}
	if h.slept >= DefaultReadyTimeout {
		t.Fatalf("waited %s on a gateway the service manager had restarted %d times", h.slept, crashLoopRestarts)
	}
}

// migratedBy records what the new gateway says it did to its databases.
func (h *host) migratedBy(runs ...upgrade.MigrationRun) func(int) {
	return func(starts int) {
		if starts == 1 {
			h.json(h.spool(upgrade.MigratedFile), upgrade.Migrated{Version: offered, Runs: runs})
			return
		}
		h.answer()
	}
}

func TestAFailedUpgradeThatMigratedPostgresIsNotRolledBack(t *testing.T) {
	h := newHost(t)
	h.svc.onStart = h.migratedBy(upgrade.MigrationRun{Dialect: upgrade.DialectPostgres, Done: true})
	st := h.run()
	if st.Phase != upgrade.PhaseFailed || st.Reason != upgrade.ReasonMigrated {
		t.Fatalf("got %s/%q", st.Phase, st.Reason)
	}
	if got := h.installedBinary(); got != "new" {
		t.Fatalf("the %s binary was put on a schema it does not know", got)
	}
	if h.svc.stops != 1 {
		t.Fatalf("the gateway was stopped %d times", h.svc.stops)
	}
}

func TestAFailedUpgradeThatMigratedSQLiteWithoutABackupIsNotRolledBack(t *testing.T) {
	h := newHost(t)
	h.svc.onStart = h.migratedBy(upgrade.MigrationRun{Dialect: upgrade.DialectSQLite, Database: "/d/gateon.db", Done: true})
	if st := h.run(); st.Phase != upgrade.PhaseFailed || st.Reason != upgrade.ReasonMigrated {
		t.Fatalf("got %s/%q", st.Phase, st.Reason)
	}
}

func TestAFailedUpgradeThatMigratedSQLiteOrdersTheBackupRestored(t *testing.T) {
	h := newHost(t)
	var ordered upgrade.Status
	record := h.migratedBy(upgrade.MigrationRun{Dialect: upgrade.DialectSQLite, Database: "/d/gateon.db", Backup: "/d/gateon.db.bak", Done: true})
	h.svc.onStart = func(starts int) {
		if starts == 2 {
			data, _ := os.ReadFile(filepath.Join(h.cfg.StateDir, upgrade.StatusFile))
			_ = json.Unmarshal(data, &ordered)
		}
		record(starts)
	}
	st := h.run()
	if st.Phase != upgrade.PhaseRolledBack || h.installedBinary() != "old" {
		t.Fatalf("got %s with the %s binary", st.Phase, h.installedBinary())
	}
	if ordered.Phase != upgrade.PhaseRollingBack || !ordered.RestoreDatabase || ordered.Expect != installed {
		t.Fatalf("the old gateway was started under %+v", ordered)
	}
	if !st.RestoreDatabase {
		t.Fatal("the old gateway answered, and the outcome does not say the database was put back")
	}
}

// TestARestoreNobodyConfirmedIsNotReportedAsDone: the outcome is what the
// dashboard shows an operator deciding whether the data is intact.
func TestARestoreNobodyConfirmedIsNotReportedAsDone(t *testing.T) {
	h := newHost(t)
	h.svc.onStart = func(starts int) {
		if starts == 1 {
			h.json(h.spool(upgrade.MigratedFile), upgrade.Migrated{Version: offered, Runs: []upgrade.MigrationRun{
				{Dialect: upgrade.DialectSQLite, Database: "/d/gateon.db", Backup: "/d/gateon.db.bak", Done: true}}})
		}
	}
	st := h.run()
	if st.Phase != upgrade.PhaseRolledBack || h.installedBinary() != "old" {
		t.Fatalf("got %s with the %s binary", st.Phase, h.installedBinary())
	}
	if st.RestoreDatabase {
		t.Fatal("the old gateway never answered, and the outcome says the database was put back")
	}
}

func TestAMigrationRecordOfAnotherVersionDecidesNothing(t *testing.T) {
	h := newHost(t)
	h.svc.onStart = func(starts int) {
		if starts == 1 {
			h.json(h.spool(upgrade.MigratedFile), upgrade.Migrated{Version: "1.7.0",
				Runs: []upgrade.MigrationRun{{Dialect: upgrade.DialectPostgres, Done: true}}})
			return
		}
		h.answer()
	}
	if st := h.run(); st.Phase != upgrade.PhaseRolledBack {
		t.Fatalf("got %s: a stale migration record blocked the rollback", st.Phase)
	}
}

func TestARunningMigrationExtendsTheWaitButNotForEver(t *testing.T) {
	h := newHost(t)
	h.svc.onStart = h.migratedBy(upgrade.MigrationRun{Dialect: upgrade.DialectSQLite, Database: "/d/g.db", Backup: "/d/g.db.bak"})
	st := h.run()
	if st.Phase != upgrade.PhaseRolledBack {
		t.Fatalf("got %s", st.Phase)
	}
	// The first wait runs to maxMigrationWait; the second, for the old
	// gateway, is answered at once.
	if h.slept < maxMigrationWait || h.slept > maxMigrationWait+time.Second {
		t.Fatalf("waited %s on a migration that never finished, want %s", h.slept, maxMigrationWait)
	}
}

func TestASecondHelperDoesNotRunBesideTheFirst(t *testing.T) {
	h := newHost(t)
	_, release, err := open(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := Run(context.Background(), h.cfg); !errors.Is(err, ErrBusy) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(h.spool(upgrade.RequestFile)); err != nil {
		t.Fatalf("the busy helper consumed the request: %v", err)
	}
}

func TestTheHistoryIsBounded(t *testing.T) {
	h := newHost(t)
	h.cfg.Keys = nil // every run is refused, quickly
	for range upgrade.MaxHistory + 5 {
		h.request(offered)
		h.run()
	}
	var history []upgrade.Status
	data, _ := os.ReadFile(filepath.Join(h.cfg.StateDir, upgrade.HistoryFile))
	if err := json.Unmarshal(data, &history); err != nil || len(history) != upgrade.MaxHistory {
		t.Fatalf("history holds %d entries (%v), want %d", len(history), err, upgrade.MaxHistory)
	}
}
