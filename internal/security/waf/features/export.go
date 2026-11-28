// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package features

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/gsoultan/gateon/internal/security/waf/corpus"
	"github.com/gsoultan/gwaf/types"
)

// The bounds on what an export reads and writes. A line is one entry, and
// the gateway's own entries fit in 4 KiB; maxRows is the most rows a mimir
// dataset takes.
const (
	maxLineBytes = 64 << 10
	maxRows      = 1_000_000
)

// Export is one `gateon export-waf-features` run.
type Export struct {
	scanner     *Scanner
	perTemplate int
	seen        map[string]int
	rows        int
	// Report counts what was kept and why the rest was not.
	Report Report
}

// Report is what an export says it did, so a dataset is never taken on
// trust.
type Report struct {
	Attack, Clean int
	Duplicate     int
	// Doubtful are clean rows dropped because the strict rules match them at
	// High or Certain confidence: on an Audit Only route the origin answers
	// an attack 200 too, and the gateway cannot tell the two apart (ADR 0097).
	Doubtful int
}

// NewExport returns an export that keeps at most perTemplate clean rows of
// each request shape, scanned at paranoia level pl. Attack rows are not
// capped: they come from a corpus someone curated, and many payloads in one
// parameter is what an attack corpus is.
func NewExport(pl, perTemplate int) (*Export, error) {
	if perTemplate < 1 {
		return nil, errors.New("--per-template must be at least 1")
	}
	s, err := NewScanner(pl)
	if err != nil {
		return nil, err
	}
	return &Export{scanner: s, perTemplate: perTemplate, seen: make(map[string]int)}, nil
}

// Write reads entries from in as JSON Lines, labels each one label, and
// writes the rows it keeps to w. Lines that are blank or start with # are
// skipped, so gwaf's corpus files read as they are.
func (x *Export) Write(w *csv.Writer, in io.Reader, label string) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 4096), maxLineBytes)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		var e corpus.Entry
		if err := json.Unmarshal([]byte(text), &e); err != nil {
			return fmt.Errorf("line %d is not a corpus entry: %w", line, err)
		}
		if err := x.add(w, &e, label); err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("after line %d: %w", line, err)
	}
	return nil
}

func (x *Export) add(w *csv.Writer, e *corpus.Entry, label string) error {
	if e.Target == "" {
		return nil
	}
	key := template(e)
	if label == LabelClean && x.seen[key] >= x.perTemplate {
		x.Report.Duplicate++
		return nil
	}
	hits := x.scanner.Scan(e)
	if label == LabelClean && confident(hits) {
		x.Report.Doubtful++
		return nil
	}
	if x.rows >= maxRows {
		return fmt.Errorf("more than %d rows, the most a mimir dataset takes", maxRows)
	}
	x.rows++
	if label == LabelAttack {
		x.Report.Attack++
	} else {
		x.seen[key]++
		x.Report.Clean++
	}
	return w.Write(append(Extract(Input{Entry: e}, hits).Values(), label))
}

// template is a request's shape: its method, its path and the names of its
// parameters. An attacker who can put requests in the clean corpus can put a
// thousand of one request there; capping each shape is what stops one
// shape from outweighing every other.
func template(e *corpus.Entry) string {
	p, query, _ := strings.Cut(e.Target, "?")
	names := make([]string, 0, len(e.Args))
	for k := range e.Args {
		names = append(names, k)
	}
	if query != "" {
		for pair := range strings.SplitSeq(query, "&") {
			k, _, _ := strings.Cut(pair, "=")
			names = append(names, k)
		}
	}
	slices.Sort(names)
	return strings.ToUpper(e.Method) + " " + p + " " + strings.Join(slices.Compact(names), "&")
}

func confident(hits []Hit) bool {
	for _, h := range hits {
		if h.Confidence >= types.High {
			return true
		}
	}
	return false
}

// files is a flag that may be given more than once.
type files []string

func (f *files) String() string     { return strings.Join(*f, ",") }
func (f *files) Set(v string) error { *f = append(*f, v); return nil }

// ExportCLI is `gateon export-waf-features`: it writes a labelled CSV to
// stdout for a mimir dataset and returns the process's exit status.
func ExportCLI(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("export-waf-features", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var attacks, clean files
	fs.Var(&attacks, "attacks", "JSON Lines of requests known to be attacks (repeatable)")
	fs.Var(&clean, "clean", "JSON Lines of requests known to be clean, such as export-waf-corpus output (repeatable)")
	pl := fs.Int("paranoia", 4, "paranoia level the rows are scanned at; the advisory worker must use the same")
	per := fs.Int("per-template", 20, "most clean rows kept of one method, path and set of parameter names")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(attacks) == 0 || len(clean) == 0 {
		fmt.Fprintln(stderr, "export-waf-features: a model needs both answers: give --attacks and --clean")
		return 2
	}
	x, err := NewExport(*pl, *per)
	if err != nil {
		fmt.Fprintf(stderr, "export-waf-features: %v\n", err)
		return 2
	}
	if err := x.run(csv.NewWriter(stdout), attacks, clean); err != nil {
		fmt.Fprintf(stderr, "export-waf-features: %v\n", err)
		return 1
	}
	r := x.Report
	fmt.Fprintf(stderr, "export-waf-features: %d attack and %d clean rows; left out %d repeats of one shape "+
		"and %d clean requests the strict rules match with confidence\n", r.Attack, r.Clean, r.Duplicate, r.Doubtful)
	return 0
}

func (x *Export) run(w *csv.Writer, attacks, clean []string) error {
	if err := w.Write(append(slices.Clone(Columns), LabelColumn)); err != nil {
		return err
	}
	for _, set := range []struct {
		paths []string
		label string
	}{{attacks, LabelAttack}, {clean, LabelClean}} {
		for _, p := range set.paths {
			if err := x.writeFile(w, p, set.label); err != nil {
				return err
			}
		}
	}
	w.Flush()
	return w.Error()
}

func (x *Export) writeFile(w *csv.Writer, path, label string) error {
	f, err := os.Open(path) // #nosec G304 -- a file the operator named on the command line
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := x.Write(w, f, label); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
