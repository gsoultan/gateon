// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Command checkfolders enforces the architecture rule that a package holds at
// most ten implementation files — as a ratchet rather than as a wall.
//
// CLAUDE.md has carried "<=10 files/folder" as an `arch` veto since adoption. On
// 2026-09-03 a count showed nine packages over the limit, led by
// internal/middleware at 67 non-test files. A rule that nothing enforces and
// nine packages ignore is not a rule; it is a comment. Both available responses
// were bad: splitting all nine is a months-long refactor of the request path,
// and splitting only the largest fixes one ninth while leaving the rule just as
// unenforced for the other eight.
//
// So the limit is enforced the way `make lint-new` and checkconfig already gate
// their own backlogs. Every package at or under the limit must stay there, and
// every package over it is pinned at the count it had when this check landed.
// The nine are debt with a ceiling instead of debt with a slogan: any of them
// may shrink, none may grow, and a tenth cannot appear.
//
// The ratchet only turns one way. Shrinking a listed package below its baseline
// is also an error, whose fix is to lower the baseline in the same commit that
// earned it. Without that, a package could be split down to eight files and
// silently drift back to fifteen while still "passing".
//
// Usage:
//
//	go run ./scripts/checkfolders
//
// Test files do not count. The limit exists so that a reader can hold a package
// in their head, and _test.go files are read when you are working on the thing
// they test, not when you are trying to find it. Counting them would also push
// packages toward fewer tests, which is precisely backwards.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	// limit is arch's unit-level rule from CLAUDE.md. A package above this must
	// appear in baseline.txt with the count it is allowed to keep.
	limit        = 10
	baselinePath = "scripts/checkfolders/baseline.txt"
)

// roots are the trees holding hand-written Go. Anything outside them is
// generated, vendored or tooling, and its file count is not a design signal.
var roots = []string{"cmd", "internal", "pkg", "scripts", "tests"}

// skipDirs are directories whose Go files are emitted by a generator. Their size
// is decided by the schema, so capping it would only ever block a legitimate
// proto change.
var skipDirs = map[string]bool{
	"proto/gateon/v1": true,
}

// countable reports whether a directory entry is an implementation file. bpf2go
// output lands in internal/ebpf beside hand-written code, so it is excluded by
// name rather than by directory.
func countable(name string) bool {
	if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
		return false
	}
	return !strings.HasPrefix(name, "gateon_ebpf_bpf")
}

// skipDir reports whether a directory's whole subtree sits outside the count.
// testdata holds fixtures rather than design, dot-directories are tooling, and
// skipDirs holds generated output.
func skipDir(path, name string) bool {
	return name == "testdata" || strings.HasPrefix(name, ".") || skipDirs[filepath.ToSlash(path)]
}

// countRoot accumulates one tree's per-directory counts into counts.
func countRoot(root string, counts map[string]int) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir(path, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if countable(d.Name()) {
			counts[filepath.ToSlash(filepath.Dir(path))]++
		}
		return nil
	})
}

// countPackages walks the roots and returns non-test .go file counts per
// directory, keyed by slash-separated path relative to the repo root.
func countPackages() (map[string]int, error) {
	counts := make(map[string]int)
	for _, root := range roots {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		}
		if err := countRoot(root, counts); err != nil {
			return nil, err
		}
	}
	return counts, nil
}

// parseBaseline reads "<count> <path>" lines, ignoring blanks and # comments.
// It takes a reader rather than a filename so the only os.Open in this command
// is on a constant path: a variable one is a directory-traversal shape (G304),
// and a build-time tool is a poor place to argue about whether it is reachable.
// name appears in error messages only.
func parseBaseline(name string, r io.Reader) (map[string]int, error) {
	baseline := make(map[string]int)
	scanner := bufio.NewScanner(r)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		count, pkg, ok := strings.Cut(text, " ")
		if !ok {
			return nil, fmt.Errorf("%s:%d: want \"<count> <path>\", got %q", name, line, text)
		}
		n, err := strconv.Atoi(count)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %q is not a count: %w", name, line, count, err)
		}
		baseline[strings.TrimSpace(pkg)] = n
	}
	return baseline, scanner.Err()
}

// violation is one package failing the ratchet, with the remedy attached so the
// message tells you what to do rather than only what is wrong.
type violation struct {
	pkg    string
	detail string
}

// check compares the counted tree against the baseline. Three things fail: an
// unlisted package over the limit, a listed package above its pin, and a listed
// package below its pin whose gain has not been banked.
func check(counts, baseline map[string]int) []violation {
	var out []violation
	for pkg, n := range counts {
		allowed, listed := baseline[pkg]
		switch {
		case !listed && n > limit:
			out = append(out, violation{pkg, fmt.Sprintf(
				"has %d implementation files, over the limit of %d. Split it, or add %q to %s with a comment saying why it has to stay whole.",
				n, limit, pkg, baselinePath)})
		case listed && n > allowed:
			out = append(out, violation{pkg, fmt.Sprintf(
				"grew from %d to %d files. It is already over the limit of %d, so it may shrink but not grow: put the new code in a package of its own.",
				allowed, n, limit)})
		case listed && n <= limit:
			out = append(out, violation{pkg, fmt.Sprintf(
				"is down to %d files from a baseline of %d, which puts it back under the limit of %d. Delete its line from %s in this commit — it does not need a pin any more.",
				n, allowed, limit, baselinePath)})
		case listed && n < allowed:
			out = append(out, violation{pkg, fmt.Sprintf(
				"is down to %d files from a baseline of %d. Lower its line in %s to %d in this commit, so the ratchet holds the ground you just took.",
				n, allowed, baselinePath, n)})
		}
	}
	for pkg, allowed := range baseline {
		if _, ok := counts[pkg]; !ok {
			out = append(out, violation{pkg, fmt.Sprintf(
				"is listed in %s at %d files but no longer exists. Drop its line.", baselinePath, allowed)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].pkg < out[j].pkg })
	return out
}

func main() {
	counts, err := countPackages()
	if err != nil {
		fmt.Fprintf(os.Stderr, "checkfolders: walking the tree: %v\n", err)
		os.Exit(2)
	}
	f, err := os.Open(baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "checkfolders: reading the baseline: %v\n", err)
		os.Exit(2)
	}
	baseline, err := parseBaseline(baselinePath, f)
	_ = f.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "checkfolders: reading the baseline: %v\n", err)
		os.Exit(2)
	}

	violations := check(counts, baseline)
	if len(violations) == 0 {
		fmt.Printf("checkfolders: ok — %d packages, %d over the limit of %d and pinned\n",
			len(counts), len(baseline), limit)
		return
	}
	fmt.Fprintf(os.Stderr, "checkfolders: %d package(s) off the ratchet\n\n", len(violations))
	for _, v := range violations {
		fmt.Fprintf(os.Stderr, "  %s %s\n\n", v.pkg, v.detail)
	}
	os.Exit(1)
}
