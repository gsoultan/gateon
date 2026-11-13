// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package upgrade

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/selfupdate"
)

const (
	testSource  = "https://releases.example"
	testVersion = "1.8.3"
	testArch    = "amd64"
	testArchive = "gateon_1.8.3_linux_amd64.tar.gz"
	testBase    = testSource + "/download/v1.8.3/"
)

// mirror is a release source held in memory.
type mirror struct {
	files map[string][]byte
	calls int
}

var errNoSuchFile = errors.New("404")

func (m *mirror) Fetch(_ context.Context, url string, _ int64) ([]byte, error) {
	m.calls++
	data, ok := m.files[url]
	if !ok {
		return nil, errNoSuchFile
	}
	return data, nil
}

func (m *mirror) Download(_ context.Context, url string, w io.Writer, _ int64) error {
	m.calls++
	data, ok := m.files[url]
	if !ok {
		return errNoSuchFile
	}
	_, err := w.Write(data)
	return err
}

// published is a mirror holding a signed release, and the stager that
// trusts its key.
func published(t *testing.T) (*mirror, Stager, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	archive := []byte("the archive of 1.8.3")
	sum := sha256.Sum256(archive)
	sums := []byte(hex.EncodeToString(sum[:]) + "  " + testArchive + "\n")
	m := &mirror{files: map[string][]byte{
		testBase + ChecksumsFile: sums,
		testBase + SignatureFile: selfupdate.Sign(key, sums),
		testBase + testArchive:   archive,
	}}
	return m, Stager{DataDir: t.TempDir(), Keys: []ed25519.PublicKey{pub}, Fetch: m, Arch: testArch}, key
}

func request() Request {
	return Request{Version: testVersion, RequestedBy: "ada", RequestedAt: time.Unix(1_800_000_000, 0).UTC()}
}

func spoolFile(s Stager, name string) string { return filepath.Join(s.DataDir, SpoolName, name) }

// notRequested asserts that nothing was left for the helper to act on.
func notRequested(t *testing.T, s Stager) {
	t.Helper()
	for _, name := range []string{RequestFile, testArchive, partialFile} {
		if _, err := os.Stat(spoolFile(s, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s was left in the spool: %v", name, err)
		}
	}
}

func TestAVerifiedReleaseIsStagedWithItsRequest(t *testing.T) {
	m, s, _ := published(t)
	if err := s.Stage(context.Background(), testSource, request()); err != nil {
		t.Fatal(err)
	}
	for name, url := range map[string]string{
		testArchive: testBase + testArchive, ChecksumsFile: testBase + ChecksumsFile, SignatureFile: testBase + SignatureFile,
	} {
		got, err := os.ReadFile(spoolFile(s, name))
		if err != nil || string(got) != string(m.files[url]) {
			t.Errorf("%s in the spool is not what the source served: %v", name, err)
		}
	}
	root, err := os.OpenRoot(filepath.Join(s.DataDir, SpoolName))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	var req Request
	if err := ReadJSON(root, RequestFile, &req); err != nil || req != request() {
		t.Fatalf("the request is %+v (%v)", req, err)
	}
	if info, _ := os.Stat(filepath.Join(s.DataDir, SpoolName)); info.Mode().Perm() != spoolMode {
		t.Fatalf("the spool is %v, want %v", info.Mode().Perm(), spoolMode)
	}
}

func TestATamperedArchiveIsNotRequested(t *testing.T) {
	m, s, _ := published(t)
	m.files[testBase+testArchive] = []byte("something else entirely")
	if err := s.Stage(context.Background(), testSource, request()); !errors.Is(err, ErrChecksum) {
		t.Fatalf("got %v", err)
	}
	notRequested(t, s)
}

func TestAListSignedByAnotherKeyIsNotRequested(t *testing.T) {
	m, s, _ := published(t)
	_, other, _ := ed25519.GenerateKey(nil)
	m.files[testBase+SignatureFile] = selfupdate.Sign(other, m.files[testBase+ChecksumsFile])
	if err := s.Stage(context.Background(), testSource, request()); !errors.Is(err, selfupdate.ErrSignature) {
		t.Fatalf("got %v", err)
	}
	notRequested(t, s)
}

func TestAnUnsignedReleaseIsNotRequested(t *testing.T) {
	m, s, _ := published(t)
	delete(m.files, testBase+SignatureFile)
	if err := s.Stage(context.Background(), testSource, request()); !errors.Is(err, selfupdate.ErrSignature) {
		t.Fatalf("got %v", err)
	}
	notRequested(t, s)
}

func TestABuildWithNoKeyDownloadsNothing(t *testing.T) {
	m, s, _ := published(t)
	s.Keys = nil
	if err := s.Stage(context.Background(), testSource, request()); !errors.Is(err, selfupdate.ErrNoKey) {
		t.Fatalf("got %v", err)
	}
	if m.calls != 0 {
		t.Fatalf("a build that can verify nothing made %d requests", m.calls)
	}
}

func TestAListForAnotherReleaseIsNotRequested(t *testing.T) {
	m, s, key := published(t)
	sums := []byte(hex.EncodeToString(make([]byte, 32)) + "  gateon_1.9.0_linux_amd64.tar.gz\n")
	m.files[testBase+ChecksumsFile], m.files[testBase+SignatureFile] = sums, selfupdate.Sign(key, sums)
	if err := s.Stage(context.Background(), testSource, request()); !errors.Is(err, selfupdate.ErrMalformed) {
		t.Fatalf("got %v", err)
	}
	notRequested(t, s)
}

func TestTheSpoolHoldsOneReleaseAtATime(t *testing.T) {
	_, s, _ := published(t)
	dir := filepath.Join(s.DataDir, SpoolName)
	if err := os.MkdirAll(dir, spoolMode); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, "gateon_1.8.1_linux_amd64.tar.gz")
	record := filepath.Join(dir, MigratedFile)
	for _, path := range []string{stale, record} {
		if err := os.WriteFile(path, []byte("{}"), fileMode); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Stage(context.Background(), testSource, request()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an archive from an earlier attempt is still in the spool")
	}
	if _, err := os.Stat(record); err != nil {
		t.Fatalf("staging removed the gateway's migration record: %v", err)
	}
}
