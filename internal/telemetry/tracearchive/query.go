// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tracearchive

import (
	"bytes"
	"cmp"
	"container/heap"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

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

// ErrTooLarge is returned when a search would hold more of the archive at once
// than maxSearchHeld allows: more nodes with hours in its period, or larger
// frames, than a real archive has.
var ErrTooLarge = errors.New("the trace archive holds more for this period than one search may read at once")

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
	// budget overrides scanBudget, and holdLimit maxSearchHeld, for tests.
	budget    int
	holdLimit int64
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
	// Traces are summaries, without headers or bodies, each with the node
	// that recorded it.
	Traces []Found
	// NextCursor continues the query where this page stopped; empty once the
	// period has been read to the end.
	NextCursor string
	// Partial means the page stopped because it had examined as many traces
	// as one call may, not because it filled.
	Partial bool
	// ScannedTo is the start time of the last trace this page examined.
	ScannedTo time.Time
}

// Found is a trace a query found, and the node that recorded it.
type Found struct {
	*telemetry.TraceRecord
	Node string
}

// Search returns one page of a query, merged from every place that holds
// traces for the period: this node's live store above its hot floor, this
// node's archive below it, and every other node's archive for the whole period
// -- this node cannot see their stores, and on shared storage it can read their
// archives (ADR-0023). The sources are merged by trace key, which is also what
// the cursor holds, so pages neither repeat nor skip across them.
//
// The store is read through a snapshot taken before the floor is decided, so a
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
	srcs, err := q.sources(sourcePlan{
		view: view, floor: floor, after: after, settings: CurrentSettings(),
		hold: &holdings{limit: cmp.Or(q.holdLimit, maxSearchHeld)},
	})
	defer closeSources(srcs)
	if err != nil {
		return Result{}, err
	}
	c := &collector{limit: q.Limit, budget: cmpOr(q.budget, scanBudget), filter: q.Filter.compile()}
	if err := merge(ctx, srcs, !q.OldestFirst, c); err != nil {
		return Result{}, err
	}
	return c.result(), nil
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

// span is a period read in one direction.
type span struct {
	from, to time.Time
	desc     bool
}

// sourcePlan is what Search knows when it lays out its sources.
type sourcePlan struct {
	view     *telemetry.TraceView // nil when the store is not open
	floor    time.Time
	after    []byte
	settings Settings
	hold     *holdings
}

// sources lays out where the query's period is read from. What a source
// cannot hold -- an empty range, a node with no archived hour in it -- is left
// out.
func (q Query) sources(p sourcePlan) ([]source, error) {
	desc := !q.OldestFirst
	var out []source
	if p.view != nil {
		if from := laterOf(q.From, p.floor); from.Before(q.To) {
			it, err := p.view.Iter(telemetry.TraceScan{From: from, To: q.To, Desc: desc, After: p.after})
			if err != nil {
				return out, err
			}
			out = append(out, &storeSource{it: it, node: p.settings.Node})
		}
	}
	nodes, err := listNodes(p.settings.Dir)
	if err != nil {
		return out, err
	}
	for _, node := range nodes {
		to := q.To
		if node == p.settings.Node {
			to = earlierOf(q.To, p.floor) // the store has the rest
		}
		src, err := newArchiveSource(p.settings.Dir, node, span{from: q.From, to: to, desc: desc}, p.after, p.hold)
		if err != nil {
			return out, err
		}
		if src != nil {
			out = append(out, src)
		}
	}
	return out, nil
}

// newArchiveSource is nil when the node has nothing archived in the span, past
// the cursor.
func newArchiveSource(root, node string, sp span, after []byte, hold *holdings) (*archiveSource, error) {
	if !sp.from.Before(sp.to) {
		return nil, nil
	}
	w := newKeyWindow(sp, after)
	if bytes.Compare(w.lo, w.hi) >= 0 {
		return nil, nil
	}
	nw := w.nanos()
	segs, err := listSegments(root, node, time.Unix(0, nw.lo), time.Unix(0, nw.hi))
	if err != nil || len(segs) == 0 {
		return nil, err
	}
	if sp.desc {
		slices.Reverse(segs)
	}
	return &archiveSource{root: root, node: node, segs: segs, w: w, hold: hold}, nil
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

// source yields traces in one span's order, each once.
type source interface {
	// advance moves to the next trace and reports whether there is one.
	advance(ctx context.Context) (bool, error)
	// current is the trace advance moved to, valid until the next advance.
	current() ([]byte, *telemetry.TraceRecord, trace)
	nodeName() string
	close()
}

// storeSource reads this node's live store through a view.
type storeSource struct {
	it   *telemetry.TraceIter
	node string
	rec  telemetry.TraceRecord
	t    trace
}

func (s *storeSource) advance(context.Context) (bool, error) {
	if !s.it.Next() {
		return false, s.it.Err()
	}
	s.rec = telemetry.TraceRecord{}
	v := s.it.Value()
	s.t = trace{readable: telemetry.UnmarshalTraceSummary(v, &s.rec) == nil, size: len(v)}
	return true, nil
}

func (s *storeSource) current() ([]byte, *telemetry.TraceRecord, trace) {
	return s.it.Key(), &s.rec, s.t
}

func (s *storeSource) nodeName() string { return s.node }

func (s *storeSource) close() { _ = s.it.Close() }

func closeSources(srcs []source) {
	for _, s := range srcs {
		s.close()
	}
}

// merge offers the sources' traces to the collector in one key order until
// it has what it needs. Each source is in that order already, so a heap of
// their current traces is all the ordering there is to do.
func merge(ctx context.Context, srcs []source, desc bool, c *collector) error {
	h := &sourceHeap{desc: desc}
	for _, s := range srcs {
		ok, err := s.advance(ctx)
		if err != nil {
			return err
		}
		if ok {
			h.items = append(h.items, s)
		}
	}
	heap.Init(h)
	for n := 1; h.Len() > 0; n++ {
		if n%256 == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		top := h.items[0]
		key, rec, t := top.current()
		if !c.offer(key, rec, t, top.nodeName()) {
			return nil
		}
		ok, err := top.advance(ctx)
		if err != nil {
			return err
		}
		if ok {
			heap.Fix(h, 0)
		} else {
			heap.Pop(h)
		}
	}
	return nil
}

// sourceHeap keeps the source whose current trace comes next at the top:
// the smallest key reading forwards, the largest reading backwards.
type sourceHeap struct {
	items []source
	desc  bool
}

func (h *sourceHeap) Len() int { return len(h.items) }

func (h *sourceHeap) Less(i, j int) bool {
	a, _, _ := h.items[i].current()
	b, _, _ := h.items[j].current()
	if h.desc {
		return bytes.Compare(a, b) > 0
	}
	return bytes.Compare(a, b) < 0
}

func (h *sourceHeap) Swap(i, j int) { h.items[i], h.items[j] = h.items[j], h.items[i] }

func (h *sourceHeap) Push(x any) {
	if s, ok := x.(source); ok {
		h.items = append(h.items, s)
	}
}

func (h *sourceHeap) Pop() any {
	last := h.items[len(h.items)-1]
	h.items = h.items[:len(h.items)-1]
	return last
}

// keyWindow is where a source reads, in store keys: [lo, hi), with the cursor
// already folded in, and the direction the scan meets keys in.
type keyWindow struct {
	lo, hi []byte
	desc   bool
}

// newKeyWindow narrows a span to what lies strictly past the cursor in the
// span's direction.
func newKeyWindow(sp span, after []byte) keyWindow {
	w := keyWindow{lo: timePrefix(sp.from), hi: timePrefix(sp.to), desc: sp.desc}
	switch {
	case after == nil:
	case sp.desc && bytes.Compare(after, w.hi) < 0:
		w.hi = after
	case !sp.desc && bytes.Compare(after, w.lo) >= 0:
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
	out           []Found
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
func (c *collector) offer(key []byte, rec *telemetry.TraceRecord, t trace, node string) bool {
	c.scanned++
	c.scannedBytes += t.size
	c.last = append(c.last[:0], key...)
	if t.readable && c.filter.matches(rec) {
		kept := *rec
		c.out = append(c.out, Found{TraceRecord: &kept, Node: node})
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
