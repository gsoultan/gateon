// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package audit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/andybalholm/brotli"
)

// writeBrotliArchive compresses content into <dataDir>/audit/archives/<name>.
func writeBrotliArchive(t *testing.T, dataDir, name string, content []byte) {
	t.Helper()
	dir := filepath.Join(dataDir, "audit", "archives")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	bw := brotli.NewWriterLevel(&buf, brotli.BestCompression)
	if _, err := bw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := bw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestGetArchiveBoundsInflation: an archive is read back inflated and whole,
// and nothing bounded how large "whole" could be. A brotli stream of a few
// kilobytes inflates to megabytes, so the ceiling has to apply to the
// inflated bytes, not the file on disk.
//
// Root cause: GetArchive used io.ReadAll(brotli.NewReader(f)) with no limit.
func TestGetArchiveBoundsInflation(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("GATEON_DATA_DIR", dataDir)
	t.Setenv(archiveMaxDecodedEnv, "1") // 1 MiB, so the test stays small and fast

	t.Run("an archive past the ceiling is refused", func(t *testing.T) {
		// Highly compressible, so the file is tiny while the inflated size is
		// well past the 1 MiB ceiling -- the shape a bomb has.
		writeBrotliArchive(t, dataDir, "big.json.br", bytes.Repeat([]byte("0"), 2<<20))

		data, err := GetArchive("big.json.br")
		if err == nil {
			t.Fatalf("a 2 MiB inflated archive was returned whole (%d bytes) under a 1 MiB ceiling; "+
				"the inflate is unbounded", len(data))
		}
		if !errors.Is(err, errArchiveTooLarge) {
			t.Fatalf("err = %v, want errArchiveTooLarge", err)
		}
	})

	t.Run("an archive under the ceiling is returned intact", func(t *testing.T) {
		want := []byte(`[{"id":"1","action":"login"}]`)
		writeBrotliArchive(t, dataDir, "small.json.br", want)

		got, err := GetArchive("small.json.br")
		if err != nil {
			t.Fatalf("GetArchive: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("archive content changed: got %q, want %q", got, want)
		}
	})

	t.Run("an archive exactly at the ceiling is returned intact", func(t *testing.T) {
		want := bytes.Repeat([]byte("1"), 1<<20)
		writeBrotliArchive(t, dataDir, "edge.json.br", want)

		got, err := GetArchive("edge.json.br")
		if err != nil {
			t.Fatalf("GetArchive at exactly the ceiling: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("archive at the ceiling was altered (%d bytes, want %d)", len(got), len(want))
		}
	})
}

// TestArchiveDecodedLimitNeverLifted: a bad override keeps the default rather
// than removing the bound.
func TestArchiveDecodedLimitNeverLifted(t *testing.T) {
	for name, v := range map[string]string{"unset": "", "zero": "0", "negative": "-3", "garbage": "lots"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(archiveMaxDecodedEnv, v)
			if got := archiveDecodedLimit(); got != defaultArchiveDecodedBytes {
				t.Fatalf("limit = %d, want default %d", got, defaultArchiveDecodedBytes)
			}
		})
	}
	t.Run("override in MiB is honoured", func(t *testing.T) {
		t.Setenv(archiveMaxDecodedEnv, "8")
		if got := archiveDecodedLimit(); got != 8<<20 {
			t.Fatalf("limit = %d, want %d", got, 8<<20)
		}
	})
}
