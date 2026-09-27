// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tracearchive

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/telemetry"
)

const (
	defaultQueryLimit = 100
	maxQueryLimit     = 500
	// scanBudget is how many traces one call may examine before it returns
	// what it found and a cursor to go on from. A filter that matches almost
	// nothing would otherwise read a year of traces in one request.
	scanBudget = 200_000
	// scanByteBudget bounds the same call by the JSON it reads. A trace's path
	// and headers are the client's to size, so a count of traces alone does
	// not bound the work: two hundred thousand traces with megabyte paths is
	// two hundred gigabytes.
	scanByteBudget = 256 << 20
	// queueWait is how long a query waits for the one query slot before it is
	// told to try again.
	queueWait = 30 * time.Second
	// maxQuerySpan bounds a period: the longest retention a tier defaults to
	// is a year.
	maxQuerySpan = 400 * 24 * time.Hour
	// maxCursorLen and maxFilterLen bound inputs that are otherwise only
	// compared against: a trace key is a timestamp and an ID.
	maxCursorLen = 1024
	maxFilterLen = 256
)

// latestTime bounds a period's end well inside what a trace key can encode:
// nanoseconds since 1970 in an int64 run out in 2262.
var latestTime = time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)

// ErrInvalidQuery wraps every reason a query or a listing is refused. The
// reasons are fixed sentences, safe to show whoever sent the query.
var ErrInvalidQuery = errors.New("invalid query")

// ErrBusy is returned when the archive is doing as much reading for callers as
// it will at once.
var ErrBusy = errors.New("the trace archive is busy")

// querySlots bounds the queries reading at once to one. A query runs on one
// core; on the two-core hosts Gateon is sized for, two would be both of them,
// and decoding JSON is CPU the proxy on the same host would rather have.
var querySlots = make(chan struct{}, 1)

// Query asks for the traces whose requests started in [From, To).
type Query struct {
	From, To time.Time
	// Limit is the most traces a page holds: 100 if unset, at most 500.
	Limit int
	// Cursor continues from the page before; empty starts at the beginning.
	Cursor string
	// OldestFirst reads the period forwards. The default is newest first.
	OldestFirst bool
	Filter      Filter
	// budget overrides scanBudget, for tests.
	budget int
}

// Filter narrows a query. An empty field matches everything.
type Filter struct {
	// Status is a class: "2xx", "3xx", "4xx", "5xx", or "errors" for 4xx and 5xx.
	Status string
	// Method matches exactly, in any case.
	Method string
	// Text matches within the path, ID, source IP or service, ignoring ASCII
	// case.
	Text string
}

// Result is one page of a query.
type Result struct {
	// Traces are summaries, without headers or bodies.
	Traces []*telemetry.TraceRecord
	// NextCursor continues the query where this page stopped; empty once the
	// period has been read to the end.
	NextCursor string
	// Partial means the page stopped because it had examined as many traces
	// as one call may, not because it filled.
	Partial bool
	// ScannedTo is the start time of the last trace this page examined.
	ScannedTo time.Time
}

// Search returns one page of a query. The part of the period the live store
// still holds is read from the store; the part before that from the archive.
//
// The store is read through a snapshot taken before the split is decided, so a
// prune that lands while the archive is being read cannot delete an hour after
// the query has decided the store is where that hour is.
func Search(ctx context.Context, q Query) (Result, error) {
	after, err := q.normalize()
	if err != nil {
		return Result{}, err
	}
	release, err := takeSlot(ctx)
	if err != nil {
		return Result{}, err
	}
	defer release()
	view, err := telemetry.OpenTraceView(ctx)
	floor := time.Now().UTC()
	switch {
	case err == nil:
		defer view.Close()
		floor = view.Floor()
	case !errors.Is(err, telemetry.ErrTraceStoreClosed):
		return Result{}, err
	}
	run := &searchRun{view: view, after: after, c: &collector{
		limit: q.Limit, budget: cmpOr(q.budget, scanBudget), filter: q.Filter.compile(),
	}}
	for _, p := range q.phases(floor, CurrentSettings().Dir) {
		if err := run.phase(ctx, p); err != nil {
			return Result{}, err
		}
		if run.c.done {
			break
		}
	}
	return run.c.result(), nil
}

func takeSlot(ctx context.Context) (func(), error) {
	wait := time.NewTimer(queueWait)
	defer wait.Stop()
	select {
	case querySlots <- struct{}{}:
		return func() { <-querySlots }, nil
	case <-wait.C:
		return nil, ErrBusy
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// searchRun is one Search call's state across its phases.
type searchRun struct {
	view  *telemetry.TraceView // nil when the store is not open
	after []byte
	c     *collector
}

func cmpOr(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}

// normalize checks the query, fills in its defaults, and returns the key its
// cursor resumes after.
func (q *Query) normalize() ([]byte, error) {
	switch {
	case q.From.IsZero() || q.To.IsZero() || !q.From.Before(q.To):
		return nil, fmt.Errorf("%w: the period needs a start before its end", ErrInvalidQuery)
	case q.From.Before(time.Unix(0, 0)) || q.To.After(latestTime):
		return nil, fmt.Errorf("%w: the period must fall between 1970 and 2200", ErrInvalidQuery)
	case q.To.Sub(q.From) > maxQuerySpan:
		return nil, fmt.Errorf("%w: a period may span at most 400 days", ErrInvalidQuery)
	case !slices.Contains([]string{"", "2xx", "3xx", "4xx", "5xx", "errors"}, q.Filter.Status):
		return nil, fmt.Errorf("%w: status must be 2xx, 3xx, 4xx, 5xx or errors", ErrInvalidQuery)
	case tooLong(q.Filter.Method) || tooLong(q.Filter.Text):
		return nil, fmt.Errorf("%w: a filter may be at most %d characters", ErrInvalidQuery, maxFilterLen)
	}
	q.Limit = min(cmpOr(q.Limit, defaultQueryLimit), maxQueryLimit)
	return decodeCursor(q.Cursor)
}

// tooLong counts characters, as the message says and the dashboard's input
// does, with a byte ceiling behind it.
func tooLong(s string) bool {
	return len(s) > 4*maxFilterLen || utf8.RuneCountInString(s) > maxFilterLen
}

func decodeCursor(cursor string) ([]byte, error) {
	if cursor == "" {
		return nil, nil
	}
	key, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil || len(key) < 9 || len(key) > maxCursorLen || key[8] != ':' {
		return nil, fmt.Errorf("%w: the cursor is not one this server issued", ErrInvalidQuery)
	}
	return key, nil
}

// phase is the part of a query's period read from one place.
type phase struct {
	from, to time.Time
	desc     bool
	// archive is the archive's root, or empty to read the live store.
	archive string
}

// phases splits the period at the store's floor: the live store for what it
// holds, the archive for what came before. Newest first reads the store first.
func (q Query) phases(floor time.Time, archive string) []phase {
	desc := !q.OldestFirst
	store := phase{from: laterOf(q.From, floor), to: q.To, desc: desc}
	archived := phase{from: q.From, to: earlierOf(q.To, floor), desc: desc, archive: archive}
	ps := []phase{store, archived}
	if !desc {
		ps = []phase{archived, store}
	}
	return slices.DeleteFunc(ps, func(p phase) bool { return !p.from.Before(p.to) })
}

func laterOf(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func earlierOf(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (r *searchRun) phase(ctx context.Context, p phase) error {
	if p.archive != "" {
		return p.runArchive(ctx, r.after, r.c)
	}
	if r.view == nil {
		return nil // no store, so nothing recent to find
	}
	var rec telemetry.TraceRecord
	return r.view.Scan(ctx, telemetry.TraceScan{From: p.from, To: p.to, Desc: p.desc, After: r.after},
		func(key, value []byte) bool {
			rec = telemetry.TraceRecord{}
			return r.c.offer(key, &rec, trace{readable: telemetry.UnmarshalTraceSummary(value, &rec) == nil, size: len(value)})
		})
}

// runArchive reads the archived hours the window reaches. The window, not the
// period, picks the files: once the cursor has moved past an hour, a later page
// does not open it again only to find nothing in it.
func (p phase) runArchive(ctx context.Context, after []byte, c *collector) error {
	w := newKeyWindow(p, after)
	if bytes.Compare(w.lo, w.hi) >= 0 {
		return nil
	}
	nw := w.nanos()
	segs, err := listSegments(p.archive, time.Unix(0, nw.lo), time.Unix(0, nw.hi))
	if err != nil {
		return err
	}
	if p.desc {
		slices.Reverse(segs)
	}
	for _, info := range segs {
		if err := scanArchived(ctx, info.seg.path(p.archive), w, c); err != nil || c.done {
			return err
		}
	}
	return nil
}

// scanArchived offers the traces of one archived hour that fall in the window.
// An hour that has gone -- retention runs while queries do -- or cannot be read
// is passed over: one bad file should not blank a year of history.
func scanArchived(ctx context.Context, path string, w keyWindow, c *collector) error {
	f, err := openSegment(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			logger.Default().LogWarn("trace archive: skipping an unreadable segment", "path", path, "error", err)
		}
		return nil
	}
	defer f.Close()
	var rec telemetry.TraceRecord
	key := make([]byte, 0, 64)
	_, err = f.scan(ctx, w.nanos(), func(line []byte) bool {
		rec = telemetry.TraceRecord{}
		if telemetry.UnmarshalTraceSummary(line, &rec) != nil {
			return true
		}
		key = telemetry.AppendTraceKey(key[:0], rec.Timestamp, rec.ID)
		switch w.place(key) {
		case beforeWindow:
			return true
		case pastWindow:
			return false
		}
		return c.offer(key, &rec, trace{readable: true, size: len(line)})
	})
	if err != nil && ctx.Err() == nil {
		logger.Default().LogWarn("trace archive: stopped reading a damaged segment", "path", path, "error", err)
		return nil
	}
	return err
}

// keyWindow is where a phase reads, in store keys: [lo, hi), with the cursor
// already folded in, and the direction the scan meets keys in.
type keyWindow struct {
	lo, hi []byte
	desc   bool
}

// newKeyWindow narrows the phase's period to what lies strictly past the
// cursor in the phase's direction.
func newKeyWindow(p phase, after []byte) keyWindow {
	w := keyWindow{lo: timePrefix(p.from), hi: timePrefix(p.to), desc: p.desc}
	switch {
	case after == nil:
	case p.desc && bytes.Compare(after, w.hi) < 0:
		w.hi = after
	case !p.desc && bytes.Compare(after, w.lo) >= 0:
		// The smallest key that sorts after the cursor.
		w.lo = append(bytes.Clone(after), 0)
	}
	return w
}

// timePrefix is the key prefix of a trace that started at t.
func timePrefix(t time.Time) []byte {
	return telemetry.AppendTraceKey(nil, t, "")[:8]
}

type placement int

const (
	inWindow placement = iota
	beforeWindow
	pastWindow
)

// place says where a key falls as the scan meets it: not reached yet, in the
// window, or past its far end, after which the scan can stop.
func (w keyWindow) place(key []byte) placement {
	below, above := bytes.Compare(key, w.lo) < 0, bytes.Compare(key, w.hi) >= 0
	switch {
	case !below && !above:
		return inWindow
	case w.desc == above:
		return beforeWindow
	default:
		return pastWindow
	}
}

// nanos is the window in Unix nanoseconds, for choosing which frames of a
// file to decode. The upper end is one past the key's time, because a cursor
// is a whole key and the traces just before it may share its nanosecond.
func (w keyWindow) nanos() nanoWindow {
	return nanoWindow{
		lo:   telemetry.TraceKeyTime(w.lo).UnixNano(),
		hi:   telemetry.TraceKeyTime(w.hi).UnixNano() + 1,
		desc: w.desc,
	}
}

// collector gathers a page as the phases offer it traces in scan order.
type collector struct {
	limit, budget int
	filter        *compiledFilter
	out           []*telemetry.TraceRecord
	scanned       int
	scannedBytes  int
	last          []byte
	done, partial bool
}

// trace is what a phase knows about a trace besides the record: whether its
// JSON could be read, and how much of it there was.
type trace struct {
	readable bool
	size     int
}

// offer examines one trace and reports whether the scan should go on. A trace
// that could not be read still counts toward the budget and moves the cursor.
func (c *collector) offer(key []byte, rec *telemetry.TraceRecord, t trace) bool {
	c.scanned++
	c.scannedBytes += t.size
	c.last = append(c.last[:0], key...)
	if t.readable && c.filter.matches(rec) {
		kept := *rec
		c.out = append(c.out, &kept)
	}
	switch {
	case len(c.out) >= c.limit:
		c.done = true
	case c.scanned >= c.budget || c.scannedBytes >= scanByteBudget:
		c.done, c.partial = true, true
	}
	return !c.done
}

func (c *collector) result() Result {
	r := Result{Traces: c.out, Partial: c.partial}
	if c.done {
		r.NextCursor = base64.RawURLEncoding.EncodeToString(c.last)
	}
	if len(c.last) > 0 {
		r.ScannedTo = telemetry.TraceKeyTime(c.last)
	}
	return r
}

// compiledFilter is a Filter made ready to test thousands of traces against.
// It is used by one query on one goroutine, and reuses a buffer across them.
type compiledFilter struct {
	statusLo, statusHi byte
	method             string
	text               []byte // lower-cased
	buf                []byte
}

func (f Filter) compile() *compiledFilter {
	cf := &compiledFilter{method: f.Method, text: lowerASCII(nil, f.Text)}
	switch f.Status {
	case "errors":
		cf.statusLo, cf.statusHi = '4', '5'
	case "2xx", "3xx", "4xx", "5xx":
		cf.statusLo, cf.statusHi = f.Status[0], f.Status[0]
	}
	return cf
}

func (f *compiledFilter) matches(tr *telemetry.TraceRecord) bool {
	if f.statusLo != 0 && (len(tr.Status) != 3 || tr.Status[0] < f.statusLo || tr.Status[0] > f.statusHi) {
		return false
	}
	if f.method != "" && !strings.EqualFold(f.method, tr.Method) {
		return false
	}
	if len(f.text) == 0 {
		return true
	}
	for _, field := range [...]string{tr.Path, tr.ID, tr.SourceIP, tr.ServiceName, tr.OperationName} {
		if f.contains(field) {
			return true
		}
	}
	return false
}

// contains reports whether the filter text is within field, ignoring ASCII
// case. The field is lower-cased into the reused buffer and searched once, in
// time linear in both: a path is the client's to size, and a search that
// compares the text at every offset costs their product, which a long path and
// a long needle turn into seconds a trace.
func (f *compiledFilter) contains(field string) bool {
	f.buf = lowerASCII(f.buf[:0], field)
	return bytes.Contains(f.buf, f.text)
}

func lowerASCII(dst []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst = append(dst, c)
	}
	return dst
}
