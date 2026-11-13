// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package upgrade

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// SpoolName is the directory, under the gateway's data directory, that the
// gateway writes a release and its request into.
const SpoolName = "upgrade"

// DefaultStateDir is the helper's own directory: root-owned, world-readable.
// It holds the status the dashboard reads, the history, and the binary an
// upgrade replaced.
const DefaultStateDir = "/var/lib/gateon-upgrade"

// The files of the spool, written by the gateway.
const (
	RequestFile   = "request.json"
	ChecksumsFile = "checksums.txt"
	SignatureFile = "checksums.txt.sig"
	ReadyFile     = "ready.json"
	MigratedFile  = "migrated.json"
)

// The files of the helper's state directory.
const (
	StatusFile  = "status.json"
	HistoryFile = "history.json"
)

// The bounds on what either side reads. Every file here crosses a privilege
// boundary in one direction or the other, so none is read without a ceiling.
const (
	// MaxArchiveBytes bounds a release archive. The archive of 1.8 is under
	// 60 MB; the ceiling leaves room for growth and none for a disk-filling
	// download.
	MaxArchiveBytes = 400 << 20
	// MaxBinaryBytes bounds the binary unpacked from an archive, so a small
	// archive cannot expand to fill /usr.
	MaxBinaryBytes = 1 << 30
	// MaxJSONBytes bounds every JSON file named above.
	MaxJSONBytes = 64 << 10
	// MaxHistory is how many finished upgrades the helper remembers.
	MaxHistory = 20
	// maxRequestedBy bounds the name a request carries.
	maxRequestedBy = 128
)

// Request asks the helper to install a release that is already in the spool.
// It names a version and nothing else that matters: which file, which hash
// and whether it may be installed are decided by the signed release list,
// not by this file.
type Request struct {
	Version string `json:"version"`
	// RequestedBy is shown in the history. It is the gateway's word and is
	// trusted for nothing.
	RequestedBy string    `json:"requested_by,omitempty"`
	Automatic   bool      `json:"automatic,omitempty"`
	RequestedAt time.Time `json:"requested_at"`
}

// Phase is where an install stands.
type Phase string

const (
	// PhaseInstalling: the helper is verifying the release and swapping the
	// binary. The gateway is still the old one.
	PhaseInstalling Phase = "installing"
	// PhaseRestarting: the new binary is in place and the helper is waiting
	// for it to report ready.
	PhaseRestarting Phase = "restarting"
	// PhaseRollingBack: the new binary did not become ready; the old one is
	// being put back.
	PhaseRollingBack Phase = "rolling_back"
	PhaseSucceeded   Phase = "succeeded"
	PhaseRolledBack  Phase = "rolled_back"
	// PhaseRefused: nothing was installed.
	PhaseRefused Phase = "refused"
	// PhaseFailed: the new binary is installed, is not ready, and was not
	// rolled back. Reason says why.
	PhaseFailed Phase = "failed"
)

// Finished reports whether p is an outcome rather than a step.
func (p Phase) Finished() bool {
	switch p {
	case PhaseSucceeded, PhaseRolledBack, PhaseRefused, PhaseFailed:
		return true
	}
	return false
}

// Reason is why an install was refused, rolled back or left failed.
type Reason string

const (
	ReasonNone Reason = ""
	// ReasonSignature: the release list is not signed by a release key.
	ReasonSignature Reason = "signature"
	// ReasonChecksum: the archive is not the one the release list names.
	ReasonChecksum Reason = "checksum"
	// ReasonMalformed: the request, the list or the archive cannot be read.
	ReasonMalformed Reason = "malformed"
	// ReasonNotNewer: the release is not newer than the installed one.
	ReasonNotNewer Reason = "not_newer"
	// ReasonNoKey: the installed binary carries no release key.
	ReasonNoKey Reason = "no_key"
	// ReasonInstall: the binary could not be put in place.
	ReasonInstall Reason = "install"
	// ReasonNotReady: the new binary did not report ready in time.
	ReasonNotReady Reason = "not_ready"
	// ReasonMigrated: the new binary changed a database that cannot be put
	// back, so the old binary was not either.
	ReasonMigrated Reason = "migrated"
)

// Status is the helper's account of the install in hand, or of the last one.
type Status struct {
	Phase Phase `json:"phase"`
	// Target is the release being installed; Previous the one it replaces.
	Target   string `json:"target"`
	Previous string `json:"previous"`
	// Expect and Nonce are how the helper learns that a gateway came up: the
	// gateway whose version is Expect answers with Nonce in ReadyFile.
	Expect string `json:"expect,omitempty"`
	Nonce  string `json:"nonce,omitempty"`
	Reason Reason `json:"reason,omitempty"`
	// RestoreDatabase orders the gateway of version Previous to put back the
	// SQLite backup taken before Target migrated it.
	RestoreDatabase bool      `json:"restore_database,omitempty"`
	RequestedBy     string    `json:"requested_by,omitempty"`
	Automatic       bool      `json:"automatic,omitempty"`
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at,omitzero"`
}

// Ready is the gateway's answer to Status.Nonce.
type Ready struct {
	Version string `json:"version"`
	Nonce   string `json:"nonce"`
}

// The dialects a migration record names.
const (
	DialectSQLite   = "sqlite"
	DialectPostgres = "postgres"
)

// MigrationRun is one database a gateway migrated at startup.
type MigrationRun struct {
	Dialect string `json:"dialect"`
	// Database is the SQLite file; empty for PostgreSQL.
	Database string `json:"database,omitempty"`
	// Backup is the copy taken before the first migration ran; empty when
	// none was taken.
	Backup string `json:"backup,omitempty"`
	// Done is false while the backup and the migrations are still running.
	Done bool      `json:"done"`
	At   time.Time `json:"at"`
}

// maxMigrationRuns bounds Migrated.Runs. A gateway opens three stores.
const maxMigrationRuns = 8

// Migrated records that the gateway of Version changed a database schema.
type Migrated struct {
	Version string         `json:"version"`
	Runs    []MigrationRun `json:"runs"`
}

// SanitizeRequestedBy bounds a name for display and drops control characters.
func SanitizeRequestedBy(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if out = append(out, r); len(out) >= maxRequestedBy {
			break
		}
	}
	return string(out)
}

// ErrNotRegular is a file that is not a plain file: a symlink out of the
// directory, a FIFO, a device.
var ErrNotRegular = errors.New("not a regular file")

// OpenRegular opens name under root for reading and refuses anything that is
// not a regular file. os.Root keeps a symlink from leading out of the
// directory; O_NONBLOCK keeps a FIFO planted under the name from hanging the
// reader, which in the helper is root.
func OpenRegular(root *os.Root, name string) (*os.File, int64, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, 0, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		if err == nil {
			err = fmt.Errorf("%s: %w", name, ErrNotRegular)
		}
		return nil, 0, err
	}
	return f, info.Size(), nil
}

// ReadBounded returns the content of name under root, refusing a file longer
// than limit.
func ReadBounded(root *os.Root, name string, limit int64) ([]byte, error) {
	f, size, err := OpenRegular(root, name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if size > limit {
		return nil, fmt.Errorf("%s is longer than %d bytes", name, limit)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is longer than %d bytes", name, limit)
	}
	return data, nil
}

// ReadJSON decodes name under root into v. Unknown fields are refused: these
// files have two writers, and one that gained a field the other does not
// know should fail loudly rather than be half-read.
func ReadJSON(root *os.Root, name string, v any) error {
	data, err := ReadBounded(root, name, MaxJSONBytes)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s is not valid: %w", name, err)
	}
	return nil
}

// WriteJSON replaces name under root with v, atomically: a reader sees the
// old file or the new one, never part of either.
func WriteJSON(root *os.Root, name string, v any, mode os.FileMode) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", name, err)
	}
	return WriteAtomic(root, name, append(data, '\n'), mode)
}

// WriteAtomic replaces name under root with data.
func WriteAtomic(root *os.Root, name string, data []byte, mode os.FileMode) error {
	tmp := filepath.Join(filepath.Dir(name), "."+filepath.Base(name)+".tmp")
	_ = root.Remove(tmp)
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	_, werr := f.Write(data)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = root.Rename(tmp, name)
	}
	if werr != nil {
		_ = root.Remove(tmp)
		return fmt.Errorf("write %s: %w", name, werr)
	}
	return nil
}
