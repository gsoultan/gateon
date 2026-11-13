// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package helper

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"crypto/subtle"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gsoultan/gateon/internal/selfupdate/upgrade"
)

// errChecksum is an archive that is not the one the release list names.
var errChecksum = errors.New("the archive does not match the signed release list")

// errArchive is an archive that verified and still cannot be installed.
var errArchive = errors.New("the release archive cannot be installed")

// binaryName is the gateway's binary inside a release archive.
const binaryName = "gateon"

// maxArchiveEntries bounds how many entries of an archive are walked. A
// release archive holds three.
const maxArchiveEntries = 64

// copyVerified copies the gateway's archive into dst, a file only the helper
// can write, and reports whether its SHA-256 is wantHex. The copy is what is
// unpacked afterwards: the gateway owns the original and could rewrite it
// between a hash and a read.
func copyVerified(src io.Reader, dst io.Writer, wantHex string) error {
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, h), io.LimitReader(src, upgrade.MaxArchiveBytes+1))
	if err != nil {
		return fmt.Errorf("copy the release archive: %w", err)
	}
	if n > upgrade.MaxArchiveBytes {
		return fmt.Errorf("%w: the archive is longer than %d bytes", errChecksum, int64(upgrade.MaxArchiveBytes))
	}
	want, err := hex.DecodeString(wantHex)
	if err != nil || subtle.ConstantTimeCompare(h.Sum(nil), want) != 1 {
		return errChecksum
	}
	return nil
}

// extractBinary writes the gateway binary held in the verified archive r to
// dst. wantPath is the only entry it accepts, so an archive cannot choose
// what is installed by carrying a second file of the same name.
func extractBinary(r io.Reader, wantPath string, dst io.Writer) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("%w: %w", errArchive, err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for range maxArchiveEntries {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: %w", errArchive, err)
		}
		if strings.TrimPrefix(hdr.Name, "./") != wantPath {
			continue
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size <= 0 || hdr.Size > upgrade.MaxBinaryBytes {
			return fmt.Errorf("%w: %s is not a regular file of a plausible size", errArchive, wantPath)
		}
		if _, err := io.CopyN(dst, tr, hdr.Size); err != nil {
			return fmt.Errorf("%w: %w", errArchive, err)
		}
		return nil
	}
	return fmt.Errorf("%w: it holds no %s", errArchive, wantPath)
}

// elfMachines is the ELF machine of each architecture a release is built for.
var elfMachines = map[string]elf.Machine{
	"amd64": elf.EM_X86_64,
	"arm64": elf.EM_AARCH64,
}

// checkBinary refuses a file that is not an executable for this machine. It
// runs before the swap, so a mislabelled archive is refused rather than
// installed, started, found not to run, and rolled back.
func checkBinary(path, goarch string) error {
	f, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("%w: the binary is not an ELF executable: %w", errArchive, err)
	}
	defer func() { _ = f.Close() }()
	if want, known := elfMachines[goarch]; known && f.Machine != want {
		return fmt.Errorf("%w: the binary is built for %s, not %s", errArchive, f.Machine, goarch)
	}
	return nil
}

// copyFile copies src to dst, replacing dst atomically, with mode.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src) // #nosec G304 -- both paths are the helper's own: the installed binary and its state directory.
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	return writeFile(dst, mode, func(w io.Writer) error {
		_, err := io.Copy(w, io.LimitReader(in, upgrade.MaxBinaryBytes))
		return err
	})
}

// writeFile fills a temporary file beside dst and renames it over dst, so
// dst is the old file or the complete new one and never a partial write.
func writeFile(dst string, mode os.FileMode, fill func(io.Writer) error) error {
	tmp := dst + ".upgrade-tmp"
	_ = os.Remove(tmp)
	// #nosec G304 G302 -- dst is the installed binary or a file in the helper's state directory; an executable is 0755.
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	err = fill(f)
	if err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, dst)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}
