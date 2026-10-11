// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package threatarchive

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// Archiver writes expired threats to archive files. It satisfies
// telemetry.ThreatArchiver and is safe for concurrent use, though the prune
// calls it from one goroutine.
type Archiver struct {
	settings func() Settings
}

// New returns an Archiver that reads CurrentSettings on every use.
func New() *Archiver { return &Archiver{settings: CurrentSettings} }

// Enabled reports whether archiving is turned on.
func (a *Archiver) Enabled() bool { return a.settings().Enabled }

// Archive writes threats, oldest first, to a new archive file and returns nil
// only once the file is complete, synced and in place. A failure leaves no
// file behind: a truncated archive looks like a backup until someone needs it.
func (a *Archiver) Archive(ctx context.Context, threats []*telemetry.SecurityThreat) error {
	if len(threats) == 0 {
		return nil
	}
	s := a.settings()
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	name, err := newFileName(threats[0].Time, threats[len(threats)-1].Time)
	if err != nil {
		return err
	}
	if err := writeFile(ctx, s.Dir, name, threats); err != nil {
		return err
	}
	enforceBudget(s.Dir, s.MaxBytes, name)
	return nil
}

// writeFile writes the archive to a temporary file and renames it into place,
// so a reader never sees a partial archive under a real name.
func writeFile(ctx context.Context, dir, name string, threats []*telemetry.SecurityThreat) error {
	tmp, err := os.CreateTemp(dir, ".partial-*")
	if err != nil {
		return err
	}
	if err := encode(ctx, tmp, threats); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return nil
}

// encode writes one JSON object per line through gzip, then flushes and syncs.
// The gzip Close is checked rather than deferred: it writes the final block,
// so it is where a full disk shows up.
func encode(ctx context.Context, f *os.File, threats []*telemetry.SecurityThreat) error {
	gz, _ := gzip.NewWriterLevel(f, gzip.BestCompression)
	enc := json.NewEncoder(gz)
	for _, t := range threats {
		if err := ctx.Err(); err != nil {
			return errors.Join(err, gz.Close())
		}
		if err := enc.Encode(t); err != nil {
			return errors.Join(err, gz.Close())
		}
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return f.Sync()
}

// newFileName names a file after the oldest and newest threat in it, with a
// random suffix so two files covering the same span never collide.
func newFileName(first, last time.Time) (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("threats_%s_%s_%s.ndjson.gz",
		first.UTC().Format(stampLayout), last.UTC().Format(stampLayout), hex.EncodeToString(b[:])), nil
}

// enforceBudget removes the oldest archive files while the archive takes more
// than maxBytes. It never removes keep, the file just written: its rows are
// about to be deleted, so removing it would make this archive the data loss
// it exists to prevent.
func enforceBudget(dir string, maxBytes int64, keep string) {
	if maxBytes <= 0 {
		return
	}
	files, err := scan(dir)
	if err != nil {
		logger.Default().LogError("threat archive: could not list files for the size budget", "error", err)
		return
	}
	var total int64
	for _, f := range files {
		total += f.Size
	}
	// scan returns newest first, so the oldest are at the end.
	for i := len(files) - 1; i >= 0 && total > maxBytes; i-- {
		if files[i].Name == keep {
			continue
		}
		if err := os.Remove(filepath.Join(dir, files[i].Name)); err != nil {
			logger.Default().LogError("threat archive: could not remove an old file", "file", files[i].Name, "error", err)
			continue
		}
		total -= files[i].Size
	}
}
