// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package helper

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gsoultan/gateon/internal/selfupdate"
	"github.com/gsoultan/gateon/internal/selfupdate/upgrade"
)

// errNotNewer is a release the request may not install over this one.
var errNotNewer = errors.New("the release is not newer than the installed one")

// errInstall is a verified release that could not be put in place.
var errInstall = errors.New("the release could not be installed")

// stagedSuffix names the verified new binary while it waits beside the
// installed one, on the same filesystem, to be renamed over it.
const stagedSuffix = ".upgrade-new"

// stage verifies the release in the spool and unpacks its binary beside the
// installed one. It returns that path; nothing is replaced yet.
func (r *run) stage() (string, error) {
	rel, err := r.verifiedRelease()
	if err != nil {
		return "", err
	}
	name := selfupdate.ArchiveName(rel.Version, r.cfg.Arch)
	sum, listed := rel.Artifacts[name]
	if !listed {
		return "", fmt.Errorf("%w: the list names no %s", selfupdate.ErrMalformed, name)
	}
	if err := r.copyArchive(name, sum); err != nil {
		return "", err
	}
	staged := r.cfg.BinaryPath + stagedSuffix
	if err := r.unpack(strings.TrimSuffix(name, ".tar.gz")+"/"+binaryName, staged); err != nil {
		_ = os.Remove(staged)
		return "", err
	}
	return staged, nil
}

// verifiedRelease reads the release list only under a release signature,
// and holds it to the request and to the installed version.
func (r *run) verifiedRelease() (selfupdate.Release, error) {
	sums, err := upgrade.ReadBounded(r.rel, r.release(upgrade.ChecksumsFile), selfupdate.MaxChecksumsBytes)
	if err != nil {
		return selfupdate.Release{}, fmt.Errorf("%w: %w", selfupdate.ErrMalformed, err)
	}
	sig, err := upgrade.ReadBounded(r.rel, r.release(upgrade.SignatureFile), selfupdate.MaxSignatureBytes)
	if err != nil {
		return selfupdate.Release{}, fmt.Errorf("%w: %w", selfupdate.ErrSignature, err)
	}
	rel, err := selfupdate.VerifyRelease(r.cfg.Keys, sums, sig)
	if err != nil {
		return selfupdate.Release{}, err
	}
	if rel.Version.String() != strings.TrimPrefix(r.status.Target, "v") {
		return selfupdate.Release{}, fmt.Errorf("%w: the request names %s and the signed list is for %s",
			selfupdate.ErrMalformed, r.status.Target, rel.Version)
	}
	if r.cfg.AllowDowngrade {
		return rel, nil
	}
	installed, isRelease := selfupdate.ParseVersion(r.cfg.Version)
	if !isRelease || !rel.Version.Newer(installed) {
		return selfupdate.Release{}, fmt.Errorf("%w: installed %s, offered %s", errNotNewer, r.cfg.Version, rel.Version)
	}
	return rel, nil
}

// copyArchive brings the archive into the helper's directory and checks it
// against the signed SHA-256 on the way.
func (r *run) copyArchive(name, sum string) error {
	src, _, err := upgrade.OpenRegular(r.rel, r.release(name))
	if err != nil {
		return fmt.Errorf("%w: %w", errChecksum, err)
	}
	defer func() { _ = src.Close() }()
	_ = r.state.Remove(stagedFile)
	dst, err := r.state.OpenFile(stagedFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("%w: %w", errInstall, err)
	}
	err = copyVerified(src, dst, sum)
	if cerr := dst.Close(); err == nil && cerr != nil {
		err = fmt.Errorf("%w: %w", errInstall, cerr)
	}
	return err
}

// unpack writes the binary the verified archive holds at entry to staged.
func (r *run) unpack(entry, staged string) error {
	archive, err := r.state.Open(stagedFile)
	if err != nil {
		return fmt.Errorf("%w: %w", errInstall, err)
	}
	defer func() { _ = archive.Close() }()
	var unpackErr error
	err = writeFile(staged, binaryMode, func(w io.Writer) error {
		unpackErr = extractBinary(archive, entry, w)
		return unpackErr
	})
	if unpackErr != nil {
		return unpackErr
	}
	if err != nil {
		return fmt.Errorf("%w: %w", errInstall, err)
	}
	return checkBinary(staged, r.cfg.Arch)
}
