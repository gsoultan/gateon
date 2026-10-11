// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package threatarchive

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// Page sizes for List and Read: what 0 means, and the most one call returns.
const (
	DefaultLimit = 50
	MaxLimit     = 500
)

// maxDecodedBytes bounds how much one Read decompresses. An archive holds one
// prune chunk, far below this; the bound exists so a file planted in the
// archive directory cannot make a read expand without limit.
const maxDecodedBytes = 1 << 30

const stampLayout = "20060102T150405Z"

// fileNamePattern is the only shape of name Read opens. Matching the whole
// name, rather than cleaning a path, is the traversal defence: nothing with a
// separator or a dot-dot can match it.
var fileNamePattern = regexp.MustCompile(`^threats_(\d{8}T\d{6}Z)_(\d{8}T\d{6}Z)_[0-9a-f]{8}\.ndjson\.gz$`)

// ErrNotAnArchive reports a name that is not an archive file's.
var ErrNotAnArchive = errors.New("not a security threat archive file name")

// Info describes one archive file.
type Info struct {
	Name      string
	Size      int64
	CreatedAt time.Time
	// FirstAt and LastAt are the oldest and newest threat in the file.
	FirstAt, LastAt time.Time
}

// List returns one page of the archive files in dir, newest first, and how
// many there are. A missing directory is an empty archive.
func List(dir string, limit, offset int) ([]Info, int, error) {
	files, err := scan(dir)
	if err != nil {
		return nil, 0, err
	}
	lo, hi := pageBounds(len(files), limit, offset)
	return files[lo:hi], len(files), nil
}

// Read returns one page of the threats in the named file, oldest first,
// keeping only those that match search when it is set, and how many matched.
func Read(ctx context.Context, dir, name, search string, limit, offset int) ([]*telemetry.SecurityThreat, int, error) {
	if !fileNamePattern.MatchString(name) {
		return nil, 0, ErrNotAnArchive
	}
	f, err := os.Open(filepath.Join(dir, name)) // #nosec G304 -- name matched fileNamePattern, which admits no separator
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, 0, err
	}
	defer gz.Close()

	limit, offset = clampPage(limit, offset)
	needle := strings.ToLower(strings.TrimSpace(search))
	dec := json.NewDecoder(io.LimitReader(gz, maxDecodedBytes))
	var page []*telemetry.SecurityThreat
	matched := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		t := &telemetry.SecurityThreat{}
		if err := dec.Decode(t); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, 0, err
		}
		if !matches(t, needle) {
			continue
		}
		if matched >= offset && len(page) < limit {
			page = append(page, t)
		}
		matched++
	}
	return page, matched, nil
}

// matches reports whether t contains needle, already lowercased, in any field
// an operator would search a threat by. An empty needle matches everything.
func matches(t *telemetry.SecurityThreat, needle string) bool {
	if needle == "" {
		return true
	}
	for _, field := range [...]string{t.SourceIP, t.Fingerprint, t.JA4, t.Type, t.Category, t.RequestURI, t.Details} {
		if strings.Contains(strings.ToLower(field), needle) {
			return true
		}
	}
	return false
}

// scan lists every archive file in dir, newest first.
func scan(dir string) ([]Info, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var files []Info
	for _, e := range entries {
		m := fileNamePattern.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue // removed since ReadDir
		}
		first, _ := time.Parse(stampLayout, m[1])
		last, _ := time.Parse(stampLayout, m[2])
		files = append(files, Info{Name: e.Name(), Size: info.Size(), CreatedAt: info.ModTime(), FirstAt: first, LastAt: last})
	}
	// Newest threats first; the name breaks ties so the order is stable.
	slices.SortFunc(files, func(a, b Info) int {
		if c := b.LastAt.Compare(a.LastAt); c != 0 {
			return c
		}
		return strings.Compare(b.Name, a.Name)
	})
	return files, nil
}

func clampPage(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = DefaultLimit
	}
	return min(limit, MaxLimit), max(offset, 0)
}

func pageBounds(n, limit, offset int) (int, int) {
	limit, offset = clampPage(limit, offset)
	lo := min(offset, n)
	return lo, min(lo+limit, n)
}
