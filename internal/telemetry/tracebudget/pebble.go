// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tracebudget

import (
	"fmt"
	"os"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
	"github.com/gsoultan/gateon/internal/logger"
)

// Configure points opts at g: Pebble's files are created through g's backoff,
// its background errors and slow-disk events go to g, and its log lines to the
// gateway's logger. Call it before opts.EnsureDefaults.
func (g *Guard) Configure(opts *pebble.Options) {
	base := opts.FS
	if base == nil {
		base = vfs.Default
	}
	opts.FS = backoffFS{FS: base, g: g}
	opts.Logger = pebbleLogger{g: g}
	opts.EventListener = &pebble.EventListener{BackgroundError: g.BackgroundError, DiskSlow: g.DiskSlow}
}

// backoffFS holds Pebble's file creations while the disk-full backoff runs.
//
// Pebble reschedules a compaction that failed straight away (its own source
// says "TODO: count consecutive compaction errors and backoff"), so on a full
// disk the same compaction was attempted, failed, and attempted again in a
// tight loop. Every attempt starts by creating its output file, and that is
// where this waits: one attempt per backoff period instead of thousands a
// second. Pebble creates these files without holding its own lock.
type backoffFS struct {
	vfs.FS
	g *Guard
}

func (fs backoffFS) Create(name string) (vfs.File, error) {
	fs.g.wait()
	f, err := fs.FS.Create(name)
	if err != nil && isNoSpace(err) {
		fs.g.BackgroundError(err)
	}
	return f, err
}

func (fs backoffFS) ReuseForWrite(oldname, newname string) (vfs.File, error) {
	fs.g.wait()
	return fs.FS.ReuseForWrite(oldname, newname)
}

// pebbleLogger sends Pebble's own log lines to the gateway's logger.
type pebbleLogger struct{ g *Guard }

func (pebbleLogger) Infof(format string, args ...any) {
	logger.L.LogInfo("trace store: " + fmt.Sprintf(format, args...))
}

// Fatalf is Pebble finding something it cannot go on from. It exits, as
// Pebble's own logger does -- except when what it cannot go on from is a full
// disk. A write-ahead-log write that hit ENOSPC is "pebble: fatal commit
// error", and Pebble's logger answered it by ending the process: the trace
// store took the proxy down with it, every in-flight request included, to
// restart into the same full disk. That one stops the trace store for the
// life of the process instead -- its commit pipeline cannot be trusted after
// it -- and the gateway goes on serving, not ready, saying why.
func (l pebbleLogger) Fatalf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if l.g != nil && anyNoSpace(args) {
		l.g.stop("trace store stopped: the disk filled while it was writing; free space and restart the gateway", msg)
		return
	}
	logger.L.LogError("trace store: fatal: " + msg)
	os.Exit(1)
}

// anyNoSpace reports whether any of args is a disk-full error.
func anyNoSpace(args []any) bool {
	for _, a := range args {
		if err, ok := a.(error); ok && isNoSpace(err) {
			return true
		}
	}
	return false
}
