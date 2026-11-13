// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package helper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/selfupdate"
	"github.com/gsoultan/gateon/internal/selfupdate/upgrade"
)

// memorySource serves a release from memory.
type memorySource map[string][]byte

func (m memorySource) Fetch(_ context.Context, url string, _ int64) ([]byte, error) {
	data, ok := m[url]
	if !ok {
		return nil, errors.New("404 " + url)
	}
	return data, nil
}

func (m memorySource) Download(ctx context.Context, url string, w io.Writer, limit int64) error {
	data, err := m.Fetch(ctx, url, limit)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// TestWhatTheGatewayStagesTheHelperInstalls runs both halves against each
// other with nothing hand-written between them: the gateway's own code
// downloads and requests, the helper installs, and the gateway's own code
// answers. Every other test in this package writes the spool itself, so a
// file the two halves named differently would pass all of them.
func TestWhatTheGatewayStagesTheHelperInstalls(t *testing.T) {
	h := newHost(t)
	spool := filepath.Join(h.cfg.DataDir, upgrade.SpoolName)
	if err := os.RemoveAll(spool); err != nil {
		t.Fatal(err)
	}

	const source = "https://releases.example"
	tarball := archive(t, offered, h.newBin)
	sum := sha256.Sum256(tarball)
	sums := []byte(hex.EncodeToString(sum[:]) + "  " + h.archive + "\n")
	v, _ := selfupdate.ParseVersion(offered)
	files, err := selfupdate.FilesOf(source, v)
	if err != nil {
		t.Fatal(err)
	}
	stager := upgrade.Stager{
		DataDir: h.cfg.DataDir, Keys: h.cfg.Keys, Arch: testArch,
		Fetch: memorySource{
			files.Checksums():         sums,
			files.Signature():         selfupdate.Sign(h.key, sums),
			files.Artifact(h.archive): tarball,
		},
	}
	req := upgrade.Request{Version: offered, RequestedBy: "ada", RequestedAt: h.clock}
	if err := stager.Stage(context.Background(), source, req); err != nil {
		t.Fatalf("the gateway could not stage the release: %v", err)
	}

	dirs := upgrade.Dirs{Data: h.cfg.DataDir, State: h.cfg.StateDir}
	h.svc.onStart = func(int) {
		// The new gateway, started by the helper, as internal/server does.
		upgrade.Confirm(context.Background(), offered, dirs, func() bool { return true })
	}
	st := h.run()
	if st.Phase != upgrade.PhaseSucceeded || st.Target != offered || st.RequestedBy != "ada" {
		t.Fatalf("got %+v", st)
	}
	if got := h.installedBinary(); got != "new" {
		t.Fatalf("the %s binary is installed", got)
	}
	if h.slept != 0 {
		t.Fatalf("the helper waited %s for an answer that was already there", h.slept)
	}
}

// TestAGatewayOfAnotherVersionDoesNotAnswerForTheNewOne: the old binary,
// started again by a crash-looping unit, must not be taken for the new one.
func TestAGatewayOfAnotherVersionDoesNotAnswerForTheNewOne(t *testing.T) {
	h := newHost(t)
	dirs := upgrade.Dirs{Data: h.cfg.DataDir, State: h.cfg.StateDir}
	h.svc.onStart = func(int) {
		upgrade.Confirm(context.Background(), installed, dirs, func() bool { return true })
	}
	st := h.run()
	if st.Phase != upgrade.PhaseRolledBack || h.installedBinary() != "old" {
		t.Fatalf("got %s with the %s binary", st.Phase, h.installedBinary())
	}
	if h.svc.starts != 2 {
		t.Fatalf("started %d times, want the upgrade and the rollback", h.svc.starts)
	}
}
