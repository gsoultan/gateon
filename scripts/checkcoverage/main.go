// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Command checkcoverage gates test coverage against a recorded baseline.
//
// It exists because every serious defect found in this codebase in 2026 came
// out of a package with no tests: an unauthenticated UDP session exhaustion in
// pkg/l4, a remote nil-deref on the audit retention goroutine, an informer
// panic and a rule-injection in internal/k8s, an IPv6 target URL that could
// never be dialled and an inverted SRV priority in internal/discovery, alerting
// that silently dropped every threat behind a reverse proxy, and a response
// writer that reported status 0 for every implicit 200. Untested packages here
// are not correlated with defects, they predict them.
//
// The gate is a ratchet, not a target. It never asks for a number; it only
// refuses to let the tested surface shrink:
//
//   - a package that has tests today may not lose them
//   - a package may not fall more than tolerance below its recorded coverage
//
// Improvements are reported as notes so the baseline can be tightened, the same
// way scripts/checkconfig treats a field that became read.
//
// Usage:
//
//	go test -cover ./... | go run ./scripts/checkcoverage
//	go run ./scripts/checkcoverage -update < coverage.txt
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// tolerance is the coverage drop, in percentage points, tolerated before the
// gate fails. Coverage of table-driven tests moves by fractions when unrelated
// code is added, and failing CI for 0.2pp of noise would train people to bump
// the baseline reflexively -- which is how a ratchet stops ratcheting.
const tolerance = 1.0

// baselinePath is a var rather than a const so writeBaseline -- the function
// that actually chooses between the preserved header and the default -- can be
// exercised against a t.TempDir() file. Tests that only called existingHeader
// passed even with the header selection replaced by the default, i.e. with the
// exact bug they were written for.
var baselinePath = "scripts/checkcoverage/baseline.txt"

var (
	// "ok  \tgithub.com/x/y\t0.5s\tcoverage: 42.9% of statements"
	okLine = regexp.MustCompile(`^ok\s+(\S+)\s+.*coverage:\s+([0-9.]+)%`)
	// "?   \tgithub.com/x/y\t[no test files]"
	noTestLine = regexp.MustCompile(`^\?\s+(\S+)\s+\[no test files\]`)
	// With -cover, a package with no test files does not get a "?" line at all:
	// it is reported as an indented "pkg\t\tcoverage: 0.0% of statements". The
	// leading whitespace is the only thing distinguishing that from a package
	// that has tests covering nothing, so it is load-bearing.
	untestedCoverLine = regexp.MustCompile(`^\s+(\S+)\s+coverage:\s+([0-9.]+)%`)
	// "FAIL\tgithub.com/x/y\t0.4s" or "FAIL\tgithub.com/x/y [build failed]".
	// A package that fails or does not compile emits no parseable coverage for
	// itself, so without this it is simply absent from the run and every check
	// below skips it -- the gate then reports "ok" for a package it did not
	// look at. The bare "FAIL" summary line carries no package and must not
	// match, hence the required second field.
	failLine = regexp.MustCompile(`^FAIL\s+(\S+)`)
)

type result struct {
	pkg      string
	coverage float64
	hasTests bool
	// failed marks a package that reported no coverage because its tests failed
	// or did not build.
	failed bool
}

func main() {
	update := flag.Bool("update", false, "rewrite the baseline from this run")
	force := flag.Bool("force", false, "allow -update on a non-linux host")
	flag.Parse()

	got, err := parse(os.Stdin)
	if err != nil {
		fail("reading coverage output: %v", err)
	}
	if len(got) == 0 {
		fail("no coverage lines found on stdin; did you pass `go test -cover ./...` output?")
	}

	if *update {
		// Banking a baseline from a red run records "no tests" for every
		// package that failed to build, which retires it from the ratchet
		// permanently and silently -- the opposite of what -update is for.
		for _, r := range got {
			if r.failed {
				fail("refusing to write a baseline from a run with failures: "+
					"%s reported no coverage. Fix the build or the test first.", r.pkg)
			}
		}
		// The baseline describes the platform that enforces it. Packages with
		// build-tagged files -- internal/ebpf, internal/phantom, internal/logger,
		// internal/resource -- compile different code on Linux and macOS, and the
		// smaller denominator elsewhere reads as higher coverage. A baseline
		// written on a laptop therefore describes a build CI never makes, and
		// fails it on the next push. This was learned the expensive way, twice.
		if runtime.GOOS != "linux" && !*force {
			fail("refusing to write a baseline on %s: CI enforces this on linux, "+
				"and a baseline from here fails there. Take the \"Coverage ratchet\" "+
				"output from a green ci run and pipe it in, or pass -force if you "+
				"genuinely mean to.", runtime.GOOS)
		}
		if err := writeBaseline(got); err != nil {
			fail("writing baseline: %v", err)
		}
		fmt.Printf("  ok - baseline written for %d packages\n", len(got))
		return
	}

	base, err := readBaseline()
	if err != nil {
		fail("reading %s: %v", baselinePath, err)
	}

	var problems, notes []string
	for _, r := range got {
		prev, known := base[r.pkg]
		// Checked before the baseline lookup, because the point is that this
		// package produced no figure to compare: `make check-coverage` pipes
		// `go test` into this command, and a pipeline takes the exit status of
		// its last stage, so a package whose tests fail or do not compile
		// exited 0 here and the gate printed "ok" over a run that never
		// happened.
		if r.failed {
			problems = append(problems, fmt.Sprintf(
				"%s reported no coverage: its tests failed or did not build", r.pkg))
			continue
		}
		if !known {
			// A brand-new package is welcome to have no tests yet; it enters the
			// baseline at whatever it has. Refusing new packages outright would
			// gate design decisions, which is not this tool's job.
			continue
		}
		switch {
		case prev.hasTests && !r.hasTests:
			problems = append(problems, fmt.Sprintf(
				"%s had tests and now has none", r.pkg))
		case r.coverage < prev.coverage-tolerance:
			problems = append(problems, fmt.Sprintf(
				"%s fell from %.1f%% to %.1f%%", r.pkg, prev.coverage, r.coverage))
		case r.coverage > prev.coverage+tolerance:
			notes = append(notes, fmt.Sprintf(
				"%s rose from %.1f%% to %.1f%%; tighten the baseline",
				r.pkg, prev.coverage, r.coverage))
		}
	}

	sort.Strings(notes)
	for _, n := range notes {
		fmt.Printf("  note - %s\n", n)
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		for _, p := range problems {
			fmt.Fprintf(os.Stderr, "  FAIL - %s\n", p)
		}
		fmt.Fprintf(os.Stderr, "\ncoverage regressed in %d package(s). "+
			"Every serious defect found here in 2026 came out of an untested "+
			"package; this gate exists so that surface only grows.\n"+
			"If the drop is deliberate, run:\n"+
			"  go test -cover ./... | go run ./scripts/checkcoverage -update\n",
			len(problems))
		os.Exit(1)
	}

	tested := 0
	for _, r := range got {
		if r.hasTests {
			tested++
		}
	}
	fmt.Printf("  ok - coverage held across %d packages (%d with tests)\n",
		len(got), tested)
}

func parse(f *os.File) ([]result, error) {
	var out []result
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case okLine.MatchString(line):
			m := okLine.FindStringSubmatch(line)
			pct, err := strconv.ParseFloat(m[2], 64)
			if err != nil {
				return nil, err
			}
			if !seen[m[1]] {
				seen[m[1]] = true
				out = append(out, result{pkg: m[1], coverage: pct, hasTests: true})
			}
		case noTestLine.MatchString(line):
			m := noTestLine.FindStringSubmatch(line)
			if !seen[m[1]] {
				seen[m[1]] = true
				out = append(out, result{pkg: m[1], hasTests: false})
			}
		case untestedCoverLine.MatchString(line):
			m := untestedCoverLine.FindStringSubmatch(line)
			if !seen[m[1]] {
				seen[m[1]] = true
				out = append(out, result{pkg: m[1], hasTests: false})
			}
		case failLine.MatchString(line):
			m := failLine.FindStringSubmatch(line)
			if !seen[m[1]] {
				seen[m[1]] = true
				out = append(out, result{pkg: m[1], failed: true})
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].pkg < out[j].pkg })
	return out, nil
}

func readBaseline() (map[string]result, error) {
	f, err := os.Open(baselinePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := map[string]result{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("malformed baseline line: %q", line)
		}
		if fields[1] == "-" {
			out[fields[0]] = result{pkg: fields[0], hasTests: false}
			continue
		}
		pct, err := strconv.ParseFloat(strings.TrimSuffix(fields[1], "%"), 64)
		if err != nil {
			return nil, fmt.Errorf("malformed coverage in %q: %w", line, err)
		}
		out[fields[0]] = result{pkg: fields[0], coverage: pct, hasTests: true}
	}
	return out, sc.Err()
}

// defaultHeader is written only when the baseline does not exist yet.
const defaultHeader = `# Per-package coverage floors, enforced by scripts/checkcoverage.
# A package may not lose its tests, and may not fall more than
# 1.0 percentage point below the figure recorded here.
#
# "-" means the package has no tests. That is a debt, not a
# licence: it is recorded so the count cannot quietly grow.
# Regenerate with:
#   go test -cover ./... | go run ./scripts/checkcoverage -update

`

// existingHeader returns the leading comment block of the current baseline.
//
// It exists because -update used to overwrite the file with the eight-line
// default above, discarding everything else. By 2026-09-20 that was a hundred
// and thirteen lines: why four packages were mislabelled "-" while CI was
// covering them, and a per-package account of every recorded drop and the
// change that caused it. All of it reasoning a later reader leans on to tell a
// real regression from an artefact -- and all of it one -update away from
// gone, with nothing to notice, because the numbers it protects would still
// look right.
// Takes the file contents rather than a path on purpose. A path parameter put
// an os.ReadFile on a variable in a package that otherwise only reads one
// constant location, which is a G304 gosec cannot see through and would have
// needed a #nosec to silence. Passing bytes keeps the read at the constant,
// leaves this a pure function of its input, and makes the test a string
// comparison instead of a filesystem one.
func existingHeader(data []byte) string {
	var b strings.Builder
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t != "" && !strings.HasPrefix(t, "#") {
			break
		}
		b.WriteString(line)
		b.WriteString("\n")
	}

	header := b.String()
	if strings.TrimSpace(header) == "" {
		return ""
	}
	// One blank line between the block and the first entry, however the
	// existing file happened to be spaced.
	return strings.TrimRight(header, "\n") + "\n\n"
}

func writeBaseline(got []result) error {
	var b strings.Builder
	var header string
	if data, err := os.ReadFile(baselinePath); err == nil {
		header = existingHeader(data)
	}
	if header == "" {
		header = defaultHeader
	}
	b.WriteString(header)

	for _, r := range got {
		if r.hasTests {
			fmt.Fprintf(&b, "%s %.1f%%\n", r.pkg, r.coverage)
		} else {
			fmt.Fprintf(&b, "%s -\n", r.pkg)
		}
	}
	return os.WriteFile(baselinePath, []byte(b.String()), 0o600)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "checkcoverage: "+format+"\n", args...)
	os.Exit(1)
}
