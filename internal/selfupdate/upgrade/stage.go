// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package upgrade

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/gsoultan/gateon/internal/selfupdate"
)

// ErrChecksum is a downloaded archive that is not the one the signed release
// list names.
var ErrChecksum = errors.New("the downloaded archive does not match the signed release list")

// spoolMode keeps the spool to the gateway's account. The helper is root
// and reads it regardless.
const (
	spoolMode os.FileMode = 0o700
	fileMode  os.FileMode = 0o600
)

// partialFile holds an archive until its hash has matched.
const partialFile = ".download.partial"

// Fetcher reads release files. *selfupdate.Downloader is the one that runs.
type Fetcher interface {
	Fetch(ctx context.Context, url string, limit int64) ([]byte, error)
	Download(ctx context.Context, url string, w io.Writer, limit int64) error
}

// Stager brings a release into the spool and asks the helper to install it.
type Stager struct {
	// DataDir is the gateway's data directory.
	DataDir string
	Keys    []ed25519.PublicKey
	Fetch   Fetcher
	// Arch is the architecture to download for.
	Arch string
}

// Stage downloads release v from source, verifies it, and writes req beside
// it. The request is written last and atomically: the helper is started by
// that file existing, and must find everything else already complete.
//
// Verifying here is not what makes the install safe; the helper verifies
// the same bytes again and believes nothing this did. It is what keeps the
// gateway from stopping itself for a release the helper would refuse.
func (s Stager) Stage(ctx context.Context, source string, req Request) error {
	v, ok := selfupdate.ParseVersion(req.Version)
	if !ok {
		return fmt.Errorf("%w: %q is not a release version", selfupdate.ErrMalformed, req.Version)
	}
	files, err := selfupdate.FilesOf(source, v)
	if err != nil {
		return err
	}
	sums, sig, sum, err := s.release(ctx, files, v)
	if err != nil {
		return err
	}
	root, err := s.openSpool()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	name := selfupdate.ArchiveName(v, s.Arch)
	if err := s.download(ctx, root, files.Artifact(name), sum); err != nil {
		_ = root.Remove(partialFile)
		return err
	}
	if err := root.Rename(partialFile, name); err != nil {
		return fmt.Errorf("keep the release archive: %w", err)
	}
	if err := WriteAtomic(root, ChecksumsFile, sums, fileMode); err != nil {
		return err
	}
	if err := WriteAtomic(root, SignatureFile, sig, fileMode); err != nil {
		return err
	}
	return WriteJSON(root, RequestFile, req, fileMode)
}

// release fetches and verifies the release list of v, and returns it, its
// signature and the SHA-256 it gives this machine's archive.
func (s Stager) release(ctx context.Context, files selfupdate.ReleaseFiles, v selfupdate.Version) (sums, sig []byte, sum string, err error) {
	if len(s.Keys) == 0 {
		return nil, nil, "", selfupdate.ErrNoKey
	}
	if sums, err = s.Fetch.Fetch(ctx, files.Checksums(), selfupdate.MaxChecksumsBytes); err != nil {
		return nil, nil, "", err
	}
	if sig, err = s.Fetch.Fetch(ctx, files.Signature(), selfupdate.MaxSignatureBytes); err != nil {
		return nil, nil, "", fmt.Errorf("%w: %w", selfupdate.ErrSignature, err)
	}
	rel, err := selfupdate.VerifyRelease(s.Keys, sums, sig)
	if err != nil {
		return nil, nil, "", err
	}
	if rel.Version != v {
		return nil, nil, "", fmt.Errorf("%w: asked for %s and the source's list is for %s", selfupdate.ErrMalformed, v, rel.Version)
	}
	name := selfupdate.ArchiveName(v, s.Arch)
	sum, listed := rel.Artifacts[name]
	if !listed {
		return nil, nil, "", fmt.Errorf("%w: the release has no %s", selfupdate.ErrMalformed, name)
	}
	return sums, sig, sum, nil
}

// openSpool opens the spool, emptied of what an earlier attempt left: the
// spool holds one release at a time, so its size is bounded by one archive.
func (s Stager) openSpool() (*os.Root, error) {
	dir := filepath.Join(s.DataDir, SpoolName)
	if err := os.MkdirAll(dir, spoolMode); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	dirFile, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	names, _ := dirFile.Readdirnames(-1)
	_ = dirFile.Close()
	for _, name := range names {
		if name == MigratedFile || name == ReadyFile {
			continue
		}
		_ = root.RemoveAll(name)
	}
	return root, nil
}

// download writes the archive at url to the partial file and reports
// whether its SHA-256 is wantHex.
func (s Stager) download(ctx context.Context, root *os.Root, url, wantHex string) error {
	f, err := root.OpenFile(partialFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)
	if err != nil {
		return fmt.Errorf("create the download: %w", err)
	}
	h := sha256.New()
	err = s.Fetch.Download(ctx, url, io.MultiWriter(f, h), MaxArchiveBytes)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	want, err := hex.DecodeString(wantHex)
	if err != nil || subtle.ConstantTimeCompare(h.Sum(nil), want) != 1 {
		return ErrChecksum
	}
	return nil
}
