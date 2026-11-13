// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package selfupdate

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// MaxChecksumsBytes bounds the release list the gateway will read. A release
// has about twenty artifacts at under a hundred bytes a line.
const MaxChecksumsBytes = 256 << 10

// maxArtifacts bounds how many lines of a release list are kept.
const maxArtifacts = 512

// ErrMalformed is wrapped by every refusal of a release list the gateway
// cannot read.
var ErrMalformed = errors.New("the release list is not one gateon can read")

// Release is one release as its checksums.txt describes it.
type Release struct {
	Version Version
	// Artifacts maps each file of the release to its SHA-256, in hex.
	Artifacts map[string]string
}

// The archive every release publishes for each platform, which is where the
// version is read from: gateon_<version>_linux_<arch>.tar.gz.
const (
	archivePrefix = "gateon_"
	archiveSuffix = ".tar.gz"
	archiveOS     = "_linux_"
)

// ParseChecksums reads a checksums.txt: "<sha256>  <file>" per line. The
// release's version is the one its archives are named for; a list whose
// archives name two versions, or none, is refused.
func ParseChecksums(data []byte) (Release, error) {
	if len(data) > MaxChecksumsBytes {
		return Release{}, fmt.Errorf("%w: it is longer than %d bytes", ErrMalformed, MaxChecksumsBytes)
	}
	rel := Release{Artifacts: make(map[string]string)}
	found := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		sum, name, err := checksumLine(line)
		if err != nil {
			return Release{}, err
		}
		if len(rel.Artifacts) >= maxArtifacts {
			return Release{}, fmt.Errorf("%w: it lists more than %d files", ErrMalformed, maxArtifacts)
		}
		rel.Artifacts[name] = sum
		v, ok := archiveVersion(name)
		if !ok {
			continue
		}
		if found && v != rel.Version {
			return Release{}, fmt.Errorf("%w: its archives name both %s and %s", ErrMalformed, rel.Version, v)
		}
		rel.Version, found = v, true
	}
	if err := sc.Err(); err != nil {
		return Release{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if !found {
		return Release{}, fmt.Errorf("%w: it names no gateon archive", ErrMalformed)
	}
	return rel, nil
}

// checksumLine splits "<sha256>  <file>". sha256sum writes two spaces, or a
// space and "*" for binary mode; both are read.
func checksumLine(line string) (sum, name string, err error) {
	sum, name, ok := strings.Cut(line, " ")
	name = strings.TrimPrefix(strings.TrimSpace(name), "*")
	if !ok || name == "" || strings.ContainsAny(name, " \t/\\") {
		return "", "", fmt.Errorf("%w: a line is not \"<sha256>  <file>\"", ErrMalformed)
	}
	if raw, decErr := hex.DecodeString(sum); decErr != nil || len(raw) != 32 {
		return "", "", fmt.Errorf("%w: a line does not start with a SHA-256", ErrMalformed)
	}
	return strings.ToLower(sum), name, nil
}

// archiveVersion reads the version out of gateon_<version>_linux_<arch>.tar.gz.
func archiveVersion(name string) (Version, bool) {
	rest, ok := strings.CutPrefix(name, archivePrefix)
	if !ok || !strings.HasSuffix(rest, archiveSuffix) {
		return Version{}, false
	}
	ver, _, ok := strings.Cut(rest, archiveOS)
	if !ok || strings.HasPrefix(ver, "v") {
		return Version{}, false
	}
	return ParseVersion(ver)
}

// ErrNoKey is a build with no release key. It can verify nothing, so it
// installs nothing.
var ErrNoKey = errors.New("this build carries no release key, so it cannot verify a release")

// ArchiveName is the archive of release v for a Linux machine of goarch, as
// the release list names it.
func ArchiveName(v Version, goarch string) string {
	return archivePrefix + v.String() + archiveOS + goarch + archiveSuffix
}

// VerifyRelease reads a release list only if sig is a signature over it by
// one of keys. It is what stands between a downloaded file and an install:
// the gateway calls it before asking for one, and the helper that installs
// calls it again on the same bytes, trusting nothing the gateway concluded.
func VerifyRelease(keys []ed25519.PublicKey, sums, sig []byte) (Release, error) {
	if len(keys) == 0 {
		return Release{}, ErrNoKey
	}
	if err := Verify(keys, sums, sig); err != nil {
		return Release{}, err
	}
	return ParseChecksums(sums)
}
