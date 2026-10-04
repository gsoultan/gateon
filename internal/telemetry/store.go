// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"bytes"
	"cmp"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/cockroachdb/pebble"
	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/audit"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/security/mitigation"
	"github.com/gsoultan/gateon/internal/security/redact"
	"github.com/gsoultan/gateon/internal/syncutil"
	"github.com/gsoultan/gateon/internal/telemetry/blocklist"
	"github.com/gsoultan/gateon/internal/telemetry/lookupgate"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
	"github.com/gsoultan/gateon/internal/telemetry/tracebudget"
	lru "github.com/hashicorp/golang-lru"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// statusMitigated is the stored mitigation-status value meaning the threat was
// acted on. It is compared against in several queries and denormalised onto
// SecurityThreat.Mitigated, so it is spelled once here.
const statusMitigated = "mitigated"

// The complete ActionTaken vocabulary for a SecurityThreat, and the mitigation
// statuses derived from it.
//
// Exported and complete on purpose. These strings were previously spread
// across three places -- private constants here, a second set in
// internal/middleware/kind, and sixteen bare literals -- and the dashboard,
// the SIEM mapping and isMitigatingAction all compare them exactly. That is
// the same shape as the severity bug, where an upper-case value ranked below
// "low" and was counted by nothing for months.
//
// They live here rather than in kind because internal/telemetry owns
// SecurityThreat, and kind already imports this package: the reverse would be
// an import cycle. The owner of a field owns its vocabulary.
//
// Note that only Blocked, Challenged and Shunned count as mitigated
// (isMitigatingAction); Detected, Flagged and Throttled are observations, and
// the dashboard's mitigated tile deliberately excludes them.
const (
	ActionBlocked    = "blocked"
	ActionChallenged = "challenged"
	ActionShunned    = "shunned"
	ActionFlagged    = "flagged"
	ActionThrottled  = "throttled"
	// ActionDetected is recorded when a threat was observed but not stopped.
	ActionDetected = "detected"
	// ActionRedacted is recorded when a data leak was removed from a response
	// and the rest of it was sent. It is not a mitigating action: nothing was
	// refused, and the record is about the response, not a client.
	ActionRedacted = "redacted"

	statusUnmitigated = "unmitigated"
)

// isMitigatingAction reports whether an ActionTaken value means the threat was
// actually stopped rather than merely observed.
//
// This predicate was written out inline in four places, which is three chances
// for the list to drift: adding a new mitigating action meant finding every
// copy, and missing one produced a threat that shows as unmitigated in one view
// and mitigated in another.
func isMitigatingAction(action string) bool {
	switch action {
	case ActionBlocked, ActionChallenged, ActionShunned:
		return true
	default:
		return false
	}
}

// RedactHeaders replaces the value of each credential header in a header
// block -- one "Name: value" per line, as FormatHeaders writes it -- with
// [REDACTED], and masks the credentials in the query string of each header
// whose value is a URI (Referer, Location, X-Forwarded-Uri; redact.URI). It
// runs on the store's goroutine, and builds into a pooled strings.Builder
// rather than splitting the block.
//
// A trace keeps that a credential was sent, which is what a debugging session
// needs, and not what it said: the trace store is read from the dashboard,
// kept for days, and with the trace archive on, for months. Which headers carry
// one is redact.IsCredentialHeader -- Authorization, Cookie, and anything named
// like a key, token, secret, session or signature -- the vocabulary every other
// redaction uses (ADR 0060). An explicit list of seventeen names preceded it,
// and X-Session-Token, X-Amz-Signature and every vendor header nobody had
// thought of were stored as sent.
func RedactHeaders(headers string) string {
	if headers == "" {
		return ""
	}

	sb := builderPool.Get().(*strings.Builder)
	sb.Reset()
	defer builderPool.Put(sb)

	start := 0
	for {
		end := strings.IndexByte(headers[start:], '\n')
		line := headers[start:]
		if end != -1 {
			line = headers[start : start+end]
		}
		writeRedactedHeaderLine(sb, line)
		if end == -1 {
			break
		}
		sb.WriteByte('\n')
		start += end + 1
	}
	return sb.String()
}

// writeRedactedHeaderLine writes one "Name: value" line of a header block with
// its credential, if any, masked.
func writeRedactedHeaderLine(sb *strings.Builder, line string) {
	colon := strings.IndexByte(line, ':')
	switch {
	case colon <= 0:
		sb.WriteString(line)
	case redact.IsCredentialHeader(line[:colon]):
		sb.WriteString(line[:colon])
		sb.WriteString(": " + redact.Mask)
	case redact.IsURIHeader(line[:colon]):
		sb.WriteString(line[:colon+1])
		sb.WriteString(redact.URI(line[colon+1:]))
	default:
		sb.WriteString(line)
	}
}

// ParseHeaders parses a plain text header block (formatted by FormatHeaders) back into a map.
// It also supports legacy JSON-formatted headers for backward compatibility.
func ParseHeaders(s string) map[string]string {
	if s == "" {
		return nil
	}
	m := make(map[string]string)

	// Backward compatibility: if it looks like JSON, try unmarshaling it.
	if s[0] == '{' {
		if err := json.Unmarshal([]byte(s), &m); err == nil {
			return m
		}
		// If unmarshal fails, fall through to plain text parsing.
		m = make(map[string]string)
	}

	start := 0
	for {
		end := strings.IndexByte(s[start:], '\n')
		var line string
		if end == -1 {
			line = s[start:]
		} else {
			line = s[start : start+end]
		}

		if colon := strings.Index(line, ": "); colon != -1 {
			m[line[:colon]] = line[colon+2:]
		}

		if end == -1 {
			break
		}
		start += end + 1
	}
	return m
}

// CloneHeader performs a deep clone of http.Header.
func CloneHeader(h map[string][]string) map[string][]string {
	if h == nil {
		return nil
	}
	h2 := make(map[string][]string, len(h))
	for k, v := range h {
		v2 := make([]string, len(v))
		copy(v2, v)
		h2[k] = v2
	}
	return h2
}

// FormatHeaders formats multiple http.Headers into a single string.
// Optimized to minimize allocations using a pooled builder.
func FormatHeaders(h map[string][]string, trailers ...map[string][]string) string {
	if len(h) == 0 && len(trailers) == 0 {
		return ""
	}

	sb := builderPool.Get().(*strings.Builder)
	sb.Reset()
	defer builderPool.Put(sb)

	for k, v := range h {
		sb.WriteString(k)
		sb.WriteString(": ")
		for i, s := range v {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(s)
		}
		sb.WriteByte('\n')
	}
	for _, t := range trailers {
		for k, v := range t {
			sb.WriteString(k)
			sb.WriteString(": ")
			for i, s := range v {
				if i > 0 {
					sb.WriteString(", ")
				}
				sb.WriteString(s)
			}
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

// AlertingHandler is a function type for alerting integration.
type AlertingHandler func(*SecurityThreat)

var (
	onThreatAlert AlertingHandler
	alertMu       sync.RWMutex

	ThreatBroadcaster = &Broadcaster[SecurityThreat]{
		subscribers: make(map[chan SecurityThreat]struct{}),
	}

	MetricsBroadcaster = &Broadcaster[*MetricsSnapshot]{
		subscribers: make(map[chan *MetricsSnapshot]struct{}),
	}

	// addressEvidence remembers, per source address, which client classes
	// produced attack evidence there and when each last did: the escalation to
	// an IP shun (escalateAddress). map[IP]*addressSightings, ARC-bounded at
	// maxEvidenceAddresses addresses of at most ipShunMinClasses classes each.
	addressEvidence, _ = lru.NewARC(maxEvidenceAddresses)
	addressEvidenceMu  sync.Mutex

	// fingerprintSightings tracks, per JA4+, how many qualifying threats it has
	// produced and how many distinct source addresses it has been seen from.
	// map[Fingerprint]*fingerprintSighting, ARC-bounded like the map above.
	fingerprintSightings, _ = lru.NewARC(10000)
	fingerprintMu           sync.Mutex

	tracePool = sync.Pool{
		New: func() any { return &TraceRecord{} },
	}
)

func (tr *TraceRecord) Reset() {
	if tr == nil {
		return
	}
	*tr = TraceRecord{}
}

// GetTraceRecord returns a clean TraceRecord from the pool.
func GetTraceRecord() *TraceRecord {
	return tracePool.Get().(*TraceRecord)
}

func (st *SecurityThreat) Reset() {
	if st == nil {
		return
	}
	*st = SecurityThreat{}
}

var threatPool = sync.Pool{
	New: func() any { return &SecurityThreat{} },
}

func GetSecurityThreat() *SecurityThreat {
	return threatPool.Get().(*SecurityThreat)
}

type Broadcaster[T any] struct {
	mu          sync.RWMutex
	subscribers map[chan T]struct{}
}

func (b *Broadcaster[T]) Subscribe() chan T {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan T, 1000)
	if b.subscribers == nil {
		b.subscribers = make(map[chan T]struct{})
	}
	b.subscribers[ch] = struct{}{}
	return ch
}

func (b *Broadcaster[T]) Unsubscribe(ch chan T) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.subscribers == nil {
		return
	}
	if _, ok := b.subscribers[ch]; ok {
		delete(b.subscribers, ch)
		close(ch)
	}
}

func (b *Broadcaster[T]) Broadcast(data T) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.subscribers {
		select {
		case ch <- data:
		default:
			// Drain if full to make room for newest (optional, but let's just stick to non-blocking)
		}
	}
}

// SetAlertingHandler registers a callback for security threats.
func SetAlertingHandler(h AlertingHandler) {
	alertMu.Lock()
	onThreatAlert = h
	alertMu.Unlock()
}

// Persistent store for path metrics with retention control.
// Design goals:
// - Append/increment aggregated rows per (day, host, path)
// - Batch updates via a buffered channel to keep hot path non-blocking
// - Periodic pruning based on retention days
// Supports SQLite and PostgreSQL.

var (
	store   *pathStatsStore
	storeMu sync.RWMutex
)

func getStore() *pathStatsStore {
	storeMu.RLock()
	defer storeMu.RUnlock()
	return store
}

type increment struct {
	host       string
	path       string
	latS       float64
	bytesTotal uint64
	atTime     time.Time
	isDomain   bool
}

type behaviorInc struct {
	fingerprint string
	path        string
	status      int
	time        time.Time
	sourceIP    string
	userAgent   string
	ja4         string
	ja4h        string
	ja4plus     string
	host        string
}

type RequestTrace = TraceRecord

type TraceRecord struct {
	ID              string    `json:"id"`
	OperationName   string    `json:"operationName"`
	ServiceName     string    `json:"serviceName"`
	DurationMs      float64   `json:"durationMs"`
	Timestamp       time.Time `json:"timestamp,omitzero"`
	Status          string    `json:"status"`
	Path            string    `json:"path"`
	SourceIP        string    `json:"sourceIp"`
	Fingerprint     string    `json:"fingerprint"`
	CountryCode     string    `json:"countryCode"`
	UserAgent       string    `json:"userAgent"`
	Method          string    `json:"method"`
	Referer         string    `json:"referer"`
	RequestURI      string    `json:"requestUri"`
	RequestHeaders  string    `json:"requestHeaders"`
	RequestBody     string    `json:"requestBody"`
	ResponseHeaders string    `json:"responseHeaders"`
	ResponseBody    string    `json:"responseBody"`
	JA4             string    `json:"ja4"`
	JA4H            string    `json:"ja4h"`
	RouteID         string    `json:"routeId"`
	Recommendation  string    `json:"recommendation"`
	Reputation      float64   `json:"reputation"`
	// Breakdown timings in milliseconds
	EntrypointDelay float64 `json:"entrypointDelayMs"`
	RouteDelay      float64 `json:"routeDelayMs"`
	MiddlewareDelay float64 `json:"middlewareDelayMs"`
	ServiceDelay    float64 `json:"serviceDelayMs"`

	// Host is the host the request named, taken from RequestURI when the
	// trace is recorded (see requestHost). It is stored on its own because the
	// analysis reads summary traces, which leave RequestURI -- query string and
	// all -- undecoded. omitempty: traces written before it existed decode to
	// "", which every reader treats as "not recorded".
	Host string `json:"host,omitempty"`

	// PasswordAuth records that the request presented a password in its
	// Authorization header -- the Basic scheme, or Digest, whose response is
	// derived from one (see presentsPassword). The analysis reads summary
	// traces, which carry no headers, and this is how it tells HTTP Basic
	// guessing, a GET answered 401, from a stale session's poll, which is the
	// same GET answered 401. Only the scheme is read; nothing of the
	// credential is kept. omitempty: absent is false, which is also how a trace
	// written before the field existed reads.
	PasswordAuth bool `json:"passwordAuth,omitempty"`

	// Refusal is why the gateway itself refused the request, where it knows
	// (request.Refusal): "token" when its own verification refused a token the
	// request presented. The analysis reads summary traces, and this is how it
	// tells a poller re-presenting an expired session or bearer token over
	// POST from a password guess, which is the same POST answered 401. Set
	// only from the mark the refusing code wrote, never from the headers.
	// omitempty: absent is "", which is how every other trace reads.
	Refusal string `json:"refusal,omitempty"`

	// Internal fields for lazy formatting in background worker
	rawReqHeader  map[string][]string
	rawRespHeader map[string][]string
}

type SecurityThreat struct {
	ID              string    `json:"id"`
	Type            string    `json:"type"`
	SourceIP        string    `json:"sourceIp"`
	SourceIPs       []string  `json:"sourceIps,omitzero"`
	Fingerprint     string    `json:"fingerprint"`
	Score           float64   `json:"score"`
	Details         string    `json:"details"`
	Time            time.Time `json:"timestamp,omitzero"`
	Latitude        float64   `json:"latitude,omitzero"`
	Longitude       float64   `json:"longitude,omitzero"`
	JA4             string    `json:"ja4"`
	JA4H            string    `json:"ja4h"`
	RouteID         string    `json:"routeId"`
	RequestURI      string    `json:"requestUri"`
	Category        string    `json:"category"`
	Severity        string    `json:"severity"`
	ASN             string    `json:"asn"`
	ActionTaken     string    `json:"actionTaken"`
	CountryCode     string    `json:"countryCode"`
	Mitigated       bool      `json:"mitigated"`
	RequestHeaders  string    `json:"requestHeaders"`
	RequestBody     string    `json:"requestBody"`
	ResponseHeaders string    `json:"responseHeaders"`
	ResponseBody    string    `json:"responseBody"`
	UserAgent       string    `json:"userAgent"`
	Method          string    `json:"method"`
	Confidence      float64   `json:"confidence,omitzero"`
	Entropy         float64   `json:"entropy,omitzero"`
	ClusterSize     int       `json:"clusterSize,omitzero"`
	Recommendation  string    `json:"recommendation"`
	TriggeredRules  string    `json:"triggeredRules"`
	Reputation      float64   `json:"reputation"`
	// Unattributed marks a threat whose source did not choose to send it: a
	// cross-site subresource load that a page on another site made a visitor's
	// browser issue (see the honeypot). It is recorded, counted, broadcast and
	// shipped like any other threat, and held against nobody -- no reputation
	// penalty, no escalation to a fingerprint or address block, no correlation
	// signal -- because the only identity it carries is the visitor's, and each
	// of those would be a ban on the visitor. Not persisted; the threat's
	// Details say it instead.
	Unattributed bool `json:"unattributed,omitzero"`
	// Observed marks a match a control recorded and did not act on: a WAF in
	// audit-only mode, a WAF match the engine scored below the route's
	// blocking threshold, and every detection-only control -- the XSS, SQLi
	// and threat recognisers, body entropy, behavioural profiling, a device
	// posture change, a WASM guest, the analysis engine's own findings. It is
	// recorded, counted, broadcast and shipped, and held against nobody -- the
	// operator has said not to act on it, or the control let the request
	// through, so it is not evidence (ADR 0025, 0055, 0059).
	Observed bool `json:"observed,omitzero"`
	// Internal fields for lazy formatting in background worker
	rawReqHeader  map[string][]string
	rawRespHeader map[string][]string
}

// Threat types that, with typeIPMitigation and typeUserMitigation, record a
// refusal following an earlier gateway decision -- a shun or feed listing, a
// fingerprint block, a reputation score -- rather than anything the client
// just sent.
const (
	threatIPShunning      = "ip_shunning"
	threatReputationBlock = "reputation_block"
)

// HeldAgainstSource reports whether a threat may count against the client that
// sent it: lower its reputation, count towards a fingerprint block or an
// address shun, be a correlation signal, or trigger a playbook's block.
//
// Three kinds are recorded, counted and shown, and held against nobody
// (ADR 0055):
//
//   - Unattributed: the client did not choose to send it (a cross-site trap
//     load, loopback, or a data leak in a response it was served).
//   - Observed: a control recorded a match and did not act on it.
//   - A refusal that follows an earlier decision (a shun or feed listing, a
//     fingerprint block, a reputation refusal). It is the gateway's own
//     decision coming back: counting it made a refused client's every retry a
//     new penalty, and a feed listing a correlation signal (ADR 0044).
func (st *SecurityThreat) HeldAgainstSource() bool {
	if st.Unattributed || st.Observed {
		return false
	}
	switch st.Type {
	case typeIPMitigation, typeUserMitigation, threatIPShunning, threatReputationBlock:
		return false
	}
	return true
}

type UserMitigation struct {
	Fingerprint   string     `json:"fingerprint"`
	JA4H          string     `json:"ja4h"`
	Type          string     `json:"type"`
	Status        string     `json:"status"`
	Reason        string     `json:"reason"`
	Category      string     `json:"category"`
	MitigatedAt   time.Time  `json:"mitigatedAt"`
	UnmitigatedAt *time.Time `json:"unmitigatedAt,omitempty"`
	UpdatedAt     time.Time  `json:"updatedAt"`
}

type IPMitigation struct {
	IP            string     `json:"ip"`
	Status        string     `json:"status"`
	Reason        string     `json:"reason"`
	MitigatedAt   time.Time  `json:"mitigatedAt"`
	UnmitigatedAt *time.Time `json:"unmitigatedAt,omitempty"`
	UpdatedAt     time.Time  `json:"updatedAt"`
	// ExpiresAt is when the shun lifts on its own: an automatic shun
	// (ShunAutomatically) or a manual block given a duration (ADR 0037). Nil
	// for an open-ended operator block, which holds until released.
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

type CombinedMitigation struct {
	SourceType    string     `json:"sourceType"` // "ip" or "user"
	Source        string     `json:"source"`     // IP or Fingerprint
	JA4H          string     `json:"ja4h"`
	Type          string     `json:"type"`
	Category      string     `json:"category"`
	Status        string     `json:"status"`
	Reason        string     `json:"reason"`
	MitigatedAt   time.Time  `json:"mitigatedAt"`
	UnmitigatedAt *time.Time `json:"unmitigatedAt,omitempty"`
	UpdatedAt     time.Time  `json:"updatedAt"`
	// ExpiresAt is when an address shun lifts on its own -- automatic, or a
	// manual block given a duration (ADR 0037); nil otherwise.
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

type ThreatFilter struct {
	Search   string
	Category string
	Status   string // all, mitigated, detected
}

type pathStatsStore struct {
	// domains bounds the distinct Host values domain_stats will hold. The Host
	// header is the client's to choose; see storedDomain.
	domains                     *boundedLabels
	db                          *sql.DB
	pebble                      *pebble.DB
	dialect                     db.Dialect
	inCh                        chan increment
	traceInCh                   chan *TraceRecord
	threatInCh                  chan *SecurityThreat
	behaviorInCh                chan *behaviorInc
	flushCh                     chan chan struct{}
	stopCh                      chan struct{}
	stopped                     atomic.Bool
	wg                          syncutil.WaitGroup
	retentionDays               atomic.Int32
	pathStatsRetentionDays      atomic.Int32
	accessLogRetentionDays      atomic.Int32
	securityThreatRetentionDays atomic.Int32
	auditLogRetentionDays       atomic.Int32
	pruning                     atomic.Bool
	scoreCache                  *lru.ARCCache
	unmitigatedCache            *lru.ARCCache
	userMitigationCache         *lru.ARCCache
	// lookups reads the block list on the request path under a deadline,
	// one query per key and a bounded number in flight (ADR 0054).
	lookups *blockLookups
	// blocks is every block in force, read at start-up and every minute, so
	// one is enforced without a lookup (ADR 0058); blockListLoaded is closed
	// once the first read has ended.
	blocks            *blocklist.List
	blockListLoaded   chan struct{}
	traceStoreEnabled atomic.Bool
	// traceGuard stops trace writes while the disk holding the store is
	// nearly full and backs Pebble off a full one (ADR 0049).
	traceGuard *tracebudget.Guard
	// nextBudgetCheck is when the store's size is next held to its budget;
	// only the loop goroutine touches it.
	nextBudgetCheck time.Time
	// tracesPrunedThrough is where the last trace prune stopped, in Unix
	// nanoseconds: every trace older than it has been deleted. See TraceHotFloor.
	// It is kept on disk too, in traceDir, so a restart does not forget it.
	tracesPrunedThrough atomic.Int64
	traceDir            string

	// Real-time daily counters (seeded from DB at startup/rollover)
	currentReqToday       atomic.Uint64
	currentBytesToday     atomic.Uint64
	currentActiveToday    atomic.Uint64
	currentMitigatedToday atomic.Uint64
	lastResetDay          string
	resetMu               sync.Mutex
	lastTier              config.Tier
}

// PathStatsStoreReady reports whether the telemetry store initialised.
//
// This exists so a readiness probe can tell the difference between a gateway
// that is serving with observability and one that is serving blind. Startup
// deliberately does not abort when the store fails to open — refusing traffic
// because a trace database is locked would trade an outage for a logging gap —
// but the instance must not then claim to be ready, or an orchestrator will
// route production traffic to it and complete a rollout past it.
func PathStatsStoreReady() bool {
	storeMu.RLock()
	defer storeMu.RUnlock()
	return store != nil
}

// InitPathStatsStore initializes the database-backed store.
// databaseURL: sqlite:path, postgres://..., mysql://..., mariadb://...
// Plain path (e.g. "gateon.db") is treated as SQLite.
// It is safe to call multiple times; only the first call takes effect.
//
// It returns once the block list has been read (ADR 0058), or
// blockListStartWait has passed, waiting outside the store lock so nothing
// that asks for the store waits with it.
func InitPathStatsStore(databaseURL string, retentionDays int) error {
	storeMu.Lock()
	if store != nil {
		storeMu.Unlock()
		return nil
	}
	err := initStore(databaseURL, retentionDays)
	st := store
	storeMu.Unlock()
	if err == nil && st != nil {
		st.awaitBlockList()
	}
	return err
}

// resolveTraceDir picks the directory for the Pebble trace store.
//
// GATEON_TRACE_DIR overrides the location outright, so an operator can relocate
// traces without a rebuild. Otherwise Pebble is placed next to a file-backed
// SQLite DB. An in-memory DSN gets a temp dir rather than the working directory:
// such a DB is ephemeral by definition, so persisting traces beside the CWD both
// outlives its own data and litters whichever directory the process (or a
// `go test` run) happens to start from.
//
// A non-SQLite DSN has no directory to sit beside, and this used to return a
// bare relative "telemetry_pebble" — so a Postgres-backed gateway put its trace
// store in whatever directory it happened to be started from, which is the
// working directory of a systemd unit, a container image, or a developer's
// shell, and differs between them. config.DataDir is the answer the rest of the
// project already uses for exactly this question: it honours GATEON_DATA_DIR
// and GATEON_STATE_DIR and falls back to /var/lib/gateon. Where DataDir has no
// better answer it returns ".", which reproduces the old path rather than
// moving anyone's data.
func resolveTraceDir(databaseURL string, isSQLite bool) string {
	if dir := strings.TrimSpace(os.Getenv("GATEON_TRACE_DIR")); dir != "" {
		return dir
	}
	if !isSQLite {
		return filepath.Join(config.DataDir(), "telemetry_pebble")
	}
	// Same path extraction logic as db.Open, to find the DB's directory.
	dsn := strings.TrimPrefix(databaseURL, "sqlite:")
	dsn = strings.TrimPrefix(dsn, "//")
	if dsn == ":memory:" || dsn == "" {
		return filepath.Join(os.TempDir(), "gateon-telemetry-pebble")
	}
	return filepath.Join(filepath.Dir(dsn), "telemetry_pebble")
}

func initStore(databaseURL string, retentionDays int) error {
	database, dialect, err := db.Open(databaseURL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}

	if dialect.Driver == db.DriverSQLite {
		if _, err := database.Exec(SQLitePragmas); err != nil {
			_ = database.Close()
			return fmt.Errorf("sqlite pragmas: %w", err)
		}
	}

	pebbleDir := resolveTraceDir(databaseURL, dialect.Driver == db.DriverSQLite)
	// 0750: the trace store holds captured request data, so it is not for
	// every local account to read.
	_ = os.MkdirAll(pebbleDir, 0o750)
	// Size Pebble's in-memory structures by resource profile (default Pebble uses
	// an 8 MiB cache + generous memtables) and compress trace blobs with Zstd
	// (Pebble defaults to Snappy) for a smaller on-disk trace footprint. The cache
	// is created with refcount 1; Open takes its own ref, so we drop ours after.
	td := config.CurrentTierDefaults()
	cache := pebble.NewCache(td.PebbleCacheBytes)
	defer cache.Unref()
	pebbleOpts := &pebble.Options{
		Cache:        cache,
		MemTableSize: uint64(td.PebbleMemTableBytes),
		MaxOpenFiles: td.PebbleMaxOpenFiles,
	}
	guard := tracebudget.NewGuard(pebbleDir, td.PebbleMemTableBytes)
	guard.Configure(pebbleOpts)
	pebbleOpts.EnsureDefaults()

	pdb, err := pebble.Open(pebbleDir, pebbleOpts)
	if err != nil {
		_ = database.Close()
		return fmt.Errorf("open pebble: %w", err)
	}

	st := &pathStatsStore{
		domains:      &boundedLabels{max: maxDistinctDomains},
		db:           database,
		pebble:       pdb,
		dialect:      dialect,
		inCh:         make(chan increment, 4096),
		traceInCh:    make(chan *TraceRecord, 4096),
		threatInCh:   make(chan *SecurityThreat, 1024),
		behaviorInCh: make(chan *behaviorInc, 2048),
		flushCh:      make(chan chan struct{}),
		stopCh:       make(chan struct{}),
	}
	st.traceStoreEnabled.Store(td.TraceStoreEnabled)
	st.traceGuard = guard
	// The first size check a period after opening, not at once: the hourly
	// prune is not due either, and a store opened over its budget waits half
	// a minute to be brought under it.
	st.nextBudgetCheck = time.Now().Add(budgetCheckEvery)
	st.retentionDays.Store(int32(max(retentionDays, 1)))
	st.traceDir = pebbleDir
	st.tracesPrunedThrough.Store(readPrunedThrough(pebbleDir))

	if cache, err := lru.NewARC(cacheSizeFromEnv(envScoreCacheSize, cacheNameScore, defaultScoreCacheSize)); err == nil {
		st.scoreCache = cache
	}
	if cache, err := lru.NewARC(cacheSizeFromEnv(envUnmitigatedCacheSize, cacheNameUnmitigated, defaultUnmitigatedCacheSize)); err == nil {
		st.unmitigatedCache = cache
	}
	if cache, err := lru.NewARC(cacheSizeFromEnv(envUserMitigatedCacheSize, cacheNameUserMitigated, defaultUserMitigatedCacheSize)); err == nil {
		st.userMitigationCache = cache
	}
	st.lookups = newBlockLookups(st)
	st.blocks = blocklist.New(blockListBounds)
	st.blockListLoaded = make(chan struct{})

	if err := db.Migrate(database, dialect); err != nil {
		_ = pdb.Close()
		_ = database.Close()
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	// Seed today's counters before the store is published, so no threat can
	// be counted ahead of the seed. Seeded from dailyResetLoop's goroutine, the
	// seed's Store overwrote whatever the loop had already counted: the first
	// threats after a start were lost from "mitigated today", and
	// TestGetMitigatedRolling24h failed whenever the seed ran late.
	st.syncDailyBaselines(false)

	// Set global store AFTER migrations are complete to ensure any
	// background activity (triggered by loops) uses a fully migrated DB.
	store = st

	// Migration: Move existing traces from SQL to Pebble if table exists.
	// Skipped when the trace store is disabled by the resource profile.
	if st.traceStoreEnabled.Load() {
		st.wg.Go(st.migrateTracesToPebble)
	}

	// Restore volatile security counters from persisted history so the
	// dashboard reflects past activity instead of resetting to 0 on restart.
	st.wg.Go(st.restoreWAFBlockCounter)

	st.wg.Go(st.loop)
	st.wg.Go(st.dailyResetLoop)
	st.wg.Go(func() { st.blockListLoop(st.blockListLoaded) })

	return nil
}

func (s *pathStatsStore) syncTierSettings() {
	td := config.CurrentTierDefaults()

	if s.lastTier != td.Tier {
		logger.Default().LogInfo("telemetry: applying resource profile tier settings", "tier", td.Tier, "flush_interval", td.FlushIntervalSeconds, "db_max_open", td.DBMaxOpenConns, "trace_store", td.TraceStoreEnabled)
		s.lastTier = td.Tier
	}

	// Update DB pool limits
	s.db.SetMaxOpenConns(td.DBMaxOpenConns)
	s.db.SetMaxIdleConns(td.DBMaxIdleConns)

	// Update trace store toggle
	s.traceStoreEnabled.Store(td.TraceStoreEnabled)

	s.lookups.setTimeout(blockLookupTimeout(td))

	// Update retention days if not explicitly overridden in global config.
	// We read the global config directly to see if there's an override.
	gc := config.GetGlobalConfig()
	retention := td.RetentionDays
	pathRetention := int32(0)
	accessRetention := int32(0)
	threatRetention := int32(0)
	auditRetention := int32(0)

	if gc != nil && gc.Log != nil {
		if gc.Log.AccessLogRetentionDays > 0 {
			retention = int(gc.Log.AccessLogRetentionDays)
		} else if gc.Log.PathStatsRetentionDays > 0 {
			retention = int(gc.Log.PathStatsRetentionDays)
		}
		pathRetention = gc.Log.PathStatsRetentionDays
		accessRetention = gc.Log.AccessLogRetentionDays
		threatRetention = gc.Log.SecurityThreatRetentionDays
		auditRetention = gc.Log.AuditLogRetentionDays
	}
	s.retentionDays.Store(int32(max(retention, 1)))
	s.pathStatsRetentionDays.Store(pathRetention)
	s.accessLogRetentionDays.Store(accessRetention)
	s.securityThreatRetentionDays.Store(threatRetention)
	s.auditLogRetentionDays.Store(auditRetention)
}

func (s *pathStatsStore) migrateTracesToPebble() {
	if !db.TableExists(s.db, s.dialect, "traces") {
		return
	}

	// Check if traces table has data
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM traces").Scan(&count)
	if err != nil || count == 0 {
		return
	}

	logger.Default().LogInfo("telemetry: migrating existing traces to Pebble", "count", count)

	rows, err := s.db.Query("SELECT id, operation_name, service_name, duration_ms, timestamp, status, path, source_ip, fingerprint, country_code, COALESCE(user_agent, ''), COALESCE(method, ''), COALESCE(referer, ''), COALESCE(request_uri, ''), COALESCE(ja4, ''), COALESCE(ja4h, ''), COALESCE(request_headers, ''), COALESCE(request_body, ''), COALESCE(response_headers, ''), COALESCE(response_body, ''), COALESCE(route_id, ''), COALESCE(recommendation, ''), reputation, entrypoint_delay_ms, route_delay_ms, middleware_delay_ms, service_delay_ms FROM traces")
	if err != nil {
		return
	}
	defer rows.Close()

	batch := s.pebble.NewBatch()
	n := 0
	// Anything that did not make it across. Non-zero means the source table
	// stays put.
	lost := 0
	for rows.Next() {
		var tr TraceRecord
		if err := rows.Scan(&tr.ID, &tr.OperationName, &tr.ServiceName, &tr.DurationMs, &tr.Timestamp, &tr.Status, &tr.Path, &tr.SourceIP, &tr.Fingerprint, &tr.CountryCode, &tr.UserAgent, &tr.Method, &tr.Referer, &tr.RequestURI, &tr.JA4, &tr.JA4H, &tr.RequestHeaders, &tr.RequestBody, &tr.ResponseHeaders, &tr.ResponseBody, &tr.RouteID, &tr.Recommendation, &tr.Reputation, &tr.EntrypointDelay, &tr.RouteDelay, &tr.MiddlewareDelay, &tr.ServiceDelay); err != nil {
			logger.Default().LogError("telemetry: trace row could not be read for migration", "error", err)
			lost++
			continue
		}

		key := makeTraceKey(tr.Timestamp, tr.ID)
		val, err := json.Marshal(tr)
		if err != nil {
			logger.Default().LogError("telemetry: trace could not be encoded for migration",
				"id", tr.ID, "error", err)
			lost++
			continue
		}
		if err := batch.Set(key, val, pebble.NoSync); err != nil {
			logger.Default().LogError("telemetry: trace could not be staged for migration",
				"id", tr.ID, "error", err)
			lost++
			continue
		}

		n++
		if n%1000 == 0 {
			if err := batch.Commit(pebble.Sync); err != nil {
				logger.Default().LogError("telemetry: trace migration batch failed to commit",
					"error", err)
				lost += 1000
			}
			// Returned to Pebble's pool before the next one is taken; see
			// flushTraces for why Commit alone does not.
			_ = batch.Close()
			batch = s.pebble.NewBatch()
		}
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		logger.Default().LogError("telemetry: final trace migration batch failed to commit",
			"error", err)
		lost++
	}
	_ = batch.Close()
	// Checked, because a connection that drops mid-iteration ends the loop
	// with a partial count and no error anywhere else.
	if err := rows.Err(); err != nil {
		logger.Default().LogError("telemetry: trace migration stopped early",
			"error", err, "migrated", n)
		lost++
	}

	// The source table is dropped only if every row arrived. It used to be
	// dropped unconditionally, with every failure above discarded -- so a
	// migration that copied nothing still wiped the traces table and logged
	// "migration complete". That table is the forensic record: source IP,
	// JA4/JA4H, request and response headers and bodies.
	//
	// internal/audit/manager.go already learned this exact lesson, and says so
	// in a comment: "a failure at flush time ... was reported nowhere,
	// checkRetention read success, and it deleted the rows the archive was
	// supposed to be preserving."
	if lost > 0 {
		logger.Default().LogError("telemetry: trace migration incomplete; keeping the SQL traces "+
			"table so nothing is lost. It will be retried on the next start.",
			"migrated", n, "failed", lost)
		return
	}

	logger.Default().LogInfo("telemetry: migration complete, clearing SQL traces table", "migrated", n)
	if _, err := s.db.Exec("DELETE FROM traces"); err != nil {
		logger.Default().LogError("telemetry: could not clear the migrated traces table; "+
			"the next start will migrate them again", "error", err)
	}
}

func makeTraceKey(ts time.Time, id string) []byte {
	return AppendTraceKey(make([]byte, 0, 8+len(id)+1), ts, id)
}

// AppendTraceKey appends the store key of a trace to dst: its start time as
// big-endian Unix nanoseconds, a colon, and its ID. Keys sort by time, so a
// key is also a position in the timeline -- the trace archive uses one as a
// cursor into it.
func AppendTraceKey(dst []byte, ts time.Time, id string) []byte {
	dst = binary.BigEndian.AppendUint64(dst, uint64(ts.UnixNano()))
	dst = append(dst, ':')
	return append(dst, id...)
}

// TraceKeyTime returns the start time a trace key encodes.
func TraceKeyTime(key []byte) time.Time {
	if len(key) < 8 {
		return time.Time{}
	}
	return time.Unix(0, int64(binary.BigEndian.Uint64(key[:8]))).UTC()
}

type queryExecutor interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (s *pathStatsStore) getExecutor(ctx context.Context) (queryExecutor, func()) {
	if s.dialect.Driver != db.DriverPostgres {
		return s.db, func() {}
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return s.db, func() {}
	}
	return tx, func() { _ = tx.Rollback() }
}

func (s *pathStatsStore) dailyResetLoop() {
	ticker := time.NewTicker(mitigationEpochLength)
	defer ticker.Stop()

	// The initial seed of today's counters runs in InitPathStatsStore, before
	// anything can count.
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			mitigationEpoch.Add(1)
			now := time.Now().UTC()
			day := now.Format("2006-01-02")

			s.resetMu.Lock()
			if s.lastResetDay != "" && s.lastResetDay != day {
				// Day changed! Reset all "today" counters.
				s.syncDailyBaselines(true)
			}
			s.lastResetDay = day
			s.resetMu.Unlock()
		}
	}
}

func (s *pathStatsStore) syncDailyBaselines(isDayRollover bool) {
	if isDayRollover {
		s.currentReqToday.Store(0)
		s.currentBytesToday.Store(0)
		s.currentActiveToday.Store(0)
		s.currentMitigatedToday.Store(0)
		// Reset global telemetry structures for the new day
		GlobalCMS.Clear()
		GlobalHHH.Clear()
		return
	}

	now := time.Now().UTC()
	day := now.Format("2006-01-02")
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	// Traffic totals for today
	q := s.dialect.Rebind(QueryGetTotalTrafficToday)
	var rc, bsum sql.NullInt64
	if err := s.db.QueryRow(q, day).Scan(&rc, &bsum); err == nil {
		s.currentReqToday.Store(uint64(rc.Int64))
		s.currentBytesToday.Store(uint64(bsum.Int64))
	}

	// Active threats today
	qActive := s.dialect.Rebind(QueryGetActiveThreatsToday)
	var activeCount int64
	if err := s.db.QueryRow(qActive, startOfDay.Format(threatTimestampLayout)).Scan(&activeCount); err == nil {
		s.currentActiveToday.Store(uint64(activeCount))
	}

	// Mitigated threats today
	qMitigated := s.dialect.Rebind(QueryGetMitigatedThreatsToday)
	var mitigatedCount int64
	if err := s.db.QueryRow(qMitigated, startOfDay.Format(threatTimestampLayout)).Scan(&mitigatedCount); err == nil {
		s.currentMitigatedToday.Store(uint64(mitigatedCount))
	}
}

// restoreWAFBlockCounter seeds the in-memory WAF block counter from persisted
// security_threats so the "WAF Block" metric on the dashboard survives process
// restarts instead of always starting at 0. Runs once at startup with a single
// small grouped query (bounded memory and CPU).
func (s *pathStatsStore) restoreWAFBlockCounter() {
	q := s.dialect.Rebind(QueryGetWAFBlockCounts)
	rows, err := s.db.Query(q)
	if err != nil {
		logger.Default().LogError("telemetry: restore WAF block counter failed", "error", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var route string
		var count int64
		if err := rows.Scan(&route, &count); err != nil {
			continue
		}
		if count > 0 {
			MiddlewareWAFBlockedTotal.WithLabelValues(route, "restored").Add(float64(count))
		}
	}
}

func (s *pathStatsStore) upsertStmt(tx *sql.Tx) (*sql.Stmt, error) {
	q := s.dialect.Rebind(QueryUpsertPathStatsConflict)
	return tx.Prepare(q)
}

func (s *pathStatsStore) domainUpsertStmt(tx *sql.Tx) (*sql.Stmt, error) {
	q := s.dialect.Rebind(QueryUpsertDomainStatsConflict)
	return tx.Prepare(q)
}

func (s *pathStatsStore) threatInsertStmt(tx *sql.Tx) (*sql.Stmt, error) {
	q := s.dialect.Rebind("INSERT INTO security_threats (id, type, source_ip, fingerprint, score, details, timestamp, ja4, ja4h, route_id, request_uri, category, severity, asn, action_taken, country_code, latitude, longitude, request_headers, request_body, response_headers, response_body, user_agent, method, confidence, entropy, cluster_size, recommendation, triggered_rules, reputation, source_ips) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	return tx.Prepare(q)
}

// execThreat inserts one threat inside its own savepoint and reports whether it
// landed.
//
// The savepoint is what isolates a rejected row. Every engine gateon supports
// implements SAVEPOINT / ROLLBACK TO, and this runs on the background flush
// goroutine over batches of at most a few hundred, so the extra round trips are
// not on any request's path.
//
// A savepoint that cannot be created is not fatal: the insert is still
// attempted, because losing a threat to bookkeeping would be the same failure
// this function exists to prevent.
func (s *pathStatsStore) execThreat(tx *sql.Tx, stmt *sql.Stmt, th *SecurityThreat, sourceIPs string) bool {
	const sp = "gateon_threat_sp"
	savepointed := true
	if _, err := tx.Exec("SAVEPOINT " + sp); err != nil {
		savepointed = false
	}

	_, err := stmt.Exec(threatInsertArgs(th, sourceIPs)...)
	if err == nil {
		if savepointed {
			_, _ = tx.Exec("RELEASE SAVEPOINT " + sp)
		}
		return true
	}

	logger.Default().LogError("threats: insert failed", "error", err, "id", th.ID)
	if savepointed {
		// Back out only this row. The transaction is usable again afterwards,
		// which is the whole point.
		if _, rbErr := tx.Exec("ROLLBACK TO SAVEPOINT " + sp); rbErr != nil {
			logger.Default().LogError("threats: savepoint rollback failed", "error", rbErr)
		}
	}
	return false
}

// threatInsertArgs is the argument list for threatInsertStmt, with every text
// value made storable. Most of them are copied from the request that caused
// the threat -- user agent, headers, body, the payload quoted in Details -- and
// Postgres refuses a row containing NUL or a byte that is not valid UTF-8, so
// the request that carried one used to be the request that was not recorded.
func threatInsertArgs(th *SecurityThreat, sourceIPs string) []any {
	args := []any{th.ID, th.Type, th.SourceIP, th.Fingerprint, th.Score, th.Details, th.Time,
		th.JA4, th.JA4H, th.RouteID, th.RequestURI, th.Category, th.Severity, th.ASN, th.ActionTaken,
		th.CountryCode, th.Latitude, th.Longitude, th.RequestHeaders, th.RequestBody,
		th.ResponseHeaders, th.ResponseBody, th.UserAgent, th.Method, th.Confidence, th.Entropy,
		th.ClusterSize, th.Recommendation, th.TriggeredRules, th.Reputation, sourceIPs}
	for i, arg := range args {
		if text, ok := arg.(string); ok {
			args[i] = db.SafeText(text)
		}
	}
	return args
}

func (s *pathStatsStore) loop() {
	// Sync initially to ensure everything matches the tier
	s.syncTierSettings()
	timer := time.NewTimer(100 * time.Millisecond) // Start soon
	pruneTicker := time.NewTicker(1 * time.Hour)
	defer timer.Stop()
	defer pruneTicker.Stop()

	batch := make([]increment, 0, 1024)
	traceBatch := make([]*TraceRecord, 0, 1024)
	threatBatch := make([]*SecurityThreat, 0, 128)

	flush := func() {
		batch = s.flushIncrements(batch)
		traceBatch = s.flushTraces(traceBatch)
		threatBatch = s.flushThreats(threatBatch)
	}

	for {
		select {
		case inc := <-s.inCh:
			batch = append(batch, inc)
			if len(batch) >= cap(batch) {
				flush()
			}
		case tr := <-s.traceInCh:
			s.processTrace(tr)
			traceBatch = append(traceBatch, tr)
			if len(traceBatch) >= cap(traceBatch) {
				flush()
			}
		case th := <-s.threatInCh:
			s.processThreat(th)
			threatBatch = append(threatBatch, th)
			if len(threatBatch) >= cap(threatBatch) {
				flush()
			}
		case b := <-s.behaviorInCh:
			TrackBehaviorInternal(b)
		case <-timer.C:
			s.syncTierSettings()
			flush()
			s.checkTraceBudget(time.Now())
			timer.Reset(flushInterval())
		case ack := <-s.flushCh:
			batch, traceBatch, threatBatch = s.drainQueued(batch, traceBatch, threatBatch)
			flush()
			close(ack)
		case <-pruneTicker.C:
			go s.prune()
		case <-s.stopCh:
			flush()
			return
		}
	}
}

// drainQueued takes everything already waiting on the intake channels, so that
// a flush request cannot overtake the records queued ahead of it.
//
// FlushThreats promises that what was enqueued before it has been processed
// when it returns, and the release path depends on that: it flushes so that a
// threat still in the queue cannot re-penalise a client after the operator
// releases it. But the loop takes the intake and the flush request from one
// select, which picks at random among ready cases, so the flush usually ran
// with most of the queue still behind it.
//
// Bounded by what is queued on entry: the loop is the only receiver, so that
// many receives cannot block, and a producer that keeps sending cannot keep
// the flush waiting.
func (s *pathStatsStore) drainQueued(batch []increment, traces []*TraceRecord, threats []*SecurityThreat) ([]increment, []*TraceRecord, []*SecurityThreat) {
	for range len(s.threatInCh) {
		th := <-s.threatInCh
		s.processThreat(th)
		threats = append(threats, th)
	}
	for range len(s.traceInCh) {
		tr := <-s.traceInCh
		s.processTrace(tr)
		traces = append(traces, tr)
	}
	for range len(s.inCh) {
		batch = append(batch, <-s.inCh)
	}
	return batch, traces, threats
}

// flushInterval is how long the writer waits between timed flushes, taken from
// the active tier. A zero or negative configured value falls back to one second
// rather than to a hot loop.
func flushInterval() time.Duration {
	interval := time.Duration(config.CurrentTierDefaults().FlushIntervalSeconds) * time.Second
	if interval <= 0 {
		return 1 * time.Second
	}
	return interval
}

// statCounters accumulates one aggregation bucket's totals between the channel
// and the database.
type statCounters struct {
	count int
	latS  float64
	bytes uint64
}

// statKey identifies an aggregation bucket. Domain rows carry a 30-minute
// bucket; path rows do not and leave it zero.
type statKey struct {
	day      string
	host     string
	path     string
	isDomain bool
	bucket   int
}

// aggregateIncrements collapses a batch into one row per bucket. Popular paths
// arrive many times per flush, and without this each arrival is its own Exec.
func aggregateIncrements(batch []increment) map[statKey]*statCounters {
	aggregated := make(map[statKey]*statCounters, len(batch))
	for _, inc := range batch {
		at := inc.atTime.UTC()
		bucket := 0
		if inc.isDomain {
			// 30-minute buckets: hour*2 + minute/30, giving 0-47 across a day.
			bucket = at.Hour()*2 + at.Minute()/30
		}
		key := statKey{at.Format("2006-01-02"), inc.host, inc.path, inc.isDomain, bucket}

		if c, ok := aggregated[key]; ok {
			c.count++
			c.latS += inc.latS
			c.bytes += inc.bytesTotal
			continue
		}
		aggregated[key] = &statCounters{count: 1, latS: inc.latS, bytes: inc.bytesTotal}
	}
	return aggregated
}

// flushIncrements writes the aggregated path and domain counters and returns
// the batch truncated for reuse. The batch is always cleared, including when
// the transaction could not be opened: these are counters, and holding a failed
// batch across flushes would grow it without bound.
func (s *pathStatsStore) flushIncrements(batch []increment) []increment {
	if len(batch) == 0 {
		return batch
	}
	tx, err := s.db.Begin()
	if err != nil {
		logger.Default().LogError("telemetry: begin transaction failed", "error", err)
		return batch[:0]
	}
	// Rollback after a successful Commit returns sql.ErrTxDone by design, so
	// this error is expected rather than ignored. The defer is the safety net
	// for the paths that return before committing.
	defer func() { _ = tx.Rollback() }()

	// A statement that fails to prepare used to be dropped silently, and with
	// it every row of its kind: on Postgres both upserts named their columns
	// unqualified inside ON CONFLICT DO UPDATE, which Postgres refuses as
	// ambiguous, so no path or domain statistic was ever stored there and
	// nothing said so.
	pathStmt, err := s.upsertStmt(tx)
	if err != nil {
		logger.Default().LogError("path stats: prepare upsert failed; this flush's path statistics are lost", "error", err)
	}
	domainStmt, err := s.domainUpsertStmt(tx)
	if err != nil {
		logger.Default().LogError("domain stats: prepare upsert failed; this flush's domain statistics are lost", "error", err)
	}

	for key, val := range aggregateIncrements(batch) {
		switch {
		case key.isDomain && domainStmt != nil:
			if _, err := domainStmt.Exec(key.day, key.bucket, s.storedDomain(key.host), val.count, val.latS, val.bytes); err != nil {
				logger.Default().LogError("domain stats: upsert failed", "error", err)
			}
		case !key.isDomain && pathStmt != nil:
			if _, err := pathStmt.Exec(key.day, db.SafeText(key.host), db.SafeText(key.path), val.count, val.latS, val.bytes); err != nil {
				logger.Default().LogError("path stats: upsert failed", "error", err)
			}
		}
	}

	if pathStmt != nil {
		_ = pathStmt.Close()
	}
	if domainStmt != nil {
		_ = domainStmt.Close()
	}
	if err := tx.Commit(); err != nil {
		logger.Default().LogError("telemetry: stats commit failed; this flush's statistics are lost", "error", err)
	}
	return batch[:0]
}

// storedDomain is the domain_stats key for a Host value: the first
// maxDistinctDomains distinct values as themselves, the rest folded into
// LabelOverflow, each cut to a length domain_stats.domain (VARCHAR(255) on
// Postgres) accepts and made storable text.
//
// The Host header is the client's, and it was written raw. Every distinct value
// was a new row per half-hour bucket at whatever length the client sent, read
// back in full by every dashboard snapshot; and on Postgres one value longer
// than the column, or holding NUL or a byte that is not UTF-8, failed its
// upsert, which aborts the transaction -- every later statement in the flush
// failed with it and the commit rolled back every counter gathered since the
// last flush. One request per flush interval blinded the traffic charts.
func (s *pathStatsStore) storedDomain(host string) string {
	if s.domains == nil {
		return db.SafeText(truncateLabel(host))
	}
	return db.SafeText(s.domains.value(host))
}

// flushTraces writes buffered traces to Pebble and returns the batch truncated
// for reuse. Records go back to the pool either way.
func (s *pathStatsStore) flushTraces(traceBatch []*TraceRecord) []*TraceRecord {
	if len(traceBatch) == 0 {
		return traceBatch
	}
	if !s.traceGuard.Admit(len(traceBatch)) {
		return recycleTraces(traceBatch)
	}
	pb := s.pebble.NewBatch()
	// Commit does not release the batch. Pebble hands these out from a
	// sync.Pool and only Close puts one back -- Batch.release is what returns
	// it, and the commit pipeline deliberately does not call it (see the note
	// at commit.go where a failed batch is marked so it is *not* a candidate
	// for reuse, which only means anything if a successful one is). Pebble's
	// own convenience writers, DB.Set and friends, all release after
	// committing. Without this the batch's data buffer -- which grew to hold
	// every trace in the flush -- is garbage rather than reused, on the
	// telemetry write path, once per flush, forever.
	defer func() { _ = pb.Close() }()

	for _, tr := range traceBatch {
		// Timestamp is nanosecond-resolution and the ID is per-record, so the
		// key is unique in practice; Pebble Set overwrites on the off chance it
		// is not.
		val, _ := json.Marshal(tr)
		_ = pb.Set(makeTraceKey(tr.Timestamp, tr.ID), val, pebble.NoSync)
	}
	if err := pb.Commit(pebble.Sync); err != nil {
		logger.Default().LogError("pebble: trace batch commit failed", "error", err)
		s.traceGuard.BackgroundError(err)
	}
	return recycleTraces(traceBatch)
}

// recycleTraces returns a batch's records to the pool and the batch truncated
// for reuse.
func recycleTraces(traceBatch []*TraceRecord) []*TraceRecord {
	for _, tr := range traceBatch {
		tr.Reset()
		tracePool.Put(tr)
	}
	return traceBatch[:0]
}

// flushThreats writes buffered security threats and returns the batch truncated
// for reuse.
//
// Records are returned to the pool on every path, including when the
// transaction could not be opened. Previously that early exit skipped the
// recycle, so a database blip quietly drained the pool.
func (s *pathStatsStore) flushThreats(threatBatch []*SecurityThreat) []*SecurityThreat {
	if len(threatBatch) == 0 {
		return threatBatch
	}
	defer func() {
		for _, th := range threatBatch {
			th.Reset()
			threatPool.Put(th)
		}
	}()

	tx, err := s.db.Begin()
	if err != nil {
		logger.Default().LogError("threats: begin transaction failed", "error", err)
		return threatBatch[:0]
	}
	// Expected to fail with sql.ErrTxDone after a successful Commit; see
	// flushIncrements.
	defer func() { _ = tx.Rollback() }()

	stmt, err := s.threatInsertStmt(tx)
	if err != nil {
		return threatBatch[:0]
	}
	for _, th := range threatBatch {
		// Each row gets a savepoint so a single rejected threat costs that
		// threat and nothing else. Without it the first failure aborts the
		// surrounding transaction, and on Postgres every later Exec then fails
		// with 25P02 — so one malformed record silently discarded the whole
		// batch. Threats are what the Security Hub is made of; losing 127 good
		// ones to a bad one is the difference between a gap and a blind spot.
		if !s.execThreat(tx, stmt, th, strings.Join(th.SourceIPs, ",")) {
			logger.Default().LogWarn("threats: record dropped",
				"id", th.ID, "type", th.Type, "source_ip", th.SourceIP)
		}
	}
	_ = stmt.Close()
	if err := tx.Commit(); err != nil {
		logger.Default().LogError("threats: commit failed", "error", err)
	}
	return threatBatch[:0]
}

func (s *pathStatsStore) prune() {
	if s.pruning.Swap(true) {
		return
	}
	defer s.pruning.Store(false)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	s.prunePathAndDomainStats(ctx)
	s.pruneTraces()
	s.holdTraceBudget()
	s.pruneSecurityThreats(ctx)
	s.pruneAuditLogs(ctx)
	s.pruneUserMitigations(ctx)

	// Reclaim the disk space freed by the deletes above. Deleting rows/keys
	// only marks them obsolete; without these steps SQLite and Pebble keep the
	// on-disk footprint, defeating retention.
	s.reclaimSQLDisk(ctx)
}

// effectiveRetention resolves a per-category retention to the global default
// when the category-specific value is unset (<= 0).
func (s *pathStatsStore) effectiveRetention(days int32) int {
	d := int(days)
	if d <= 0 {
		d = int(s.retentionDays.Load())
	}
	return d
}

// prunePathAndDomainStats removes aggregated rows older than the retention window.
func (s *pathStatsStore) prunePathAndDomainStats(ctx context.Context) {
	days := s.effectiveRetention(s.pathStatsRetentionDays.Load())
	if days <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -days).UTC().Format("2006-01-02")
	if _, err := s.db.ExecContext(ctx, s.dialect.Rebind(QueryPrunePathStats), cutoff); err != nil {
		logger.Default().LogError("path stats: prune failed", "error", err)
	}
	if _, err := s.db.ExecContext(ctx, s.dialect.Rebind(QueryPruneDomainStats), cutoff); err != nil {
		logger.Default().LogError("domain stats: prune failed", "error", err)
	}
}

// pruneTraces removes Pebble access-log entries older than the retention window
// and compacts the freed key range so the deleted data is physically reclaimed.
func (s *pathStatsStore) pruneTraces() {
	cutoff := s.traceCutoff(time.Now())
	if cutoff.IsZero() {
		return
	}
	cutoffTime := guardTracePrune(cutoff)
	// Nothing to delete, and nothing that can be: a cutoff at or before the
	// epoch has no key below it, and UnixNano of the zero time -- which a guard
	// holding everything back could answer -- wraps to a key above every trace,
	// which would have deleted the lot.
	if !cutoffTime.After(time.Unix(0, 0)) {
		return
	}
	s.deleteTracesBefore(cutoffTime)
}

// deleteTracesBefore deletes every trace that started before cutoff and
// compacts the range so the disk is given back, and reports whether the
// delete was written.
func (s *pathStatsStore) deleteTracesBefore(cutoff time.Time) bool {
	if !s.traceGuard.Writable() {
		return false // the commit pipeline failed on a full disk; see tracebudget
	}
	startKey := make([]byte, 8) // All zeros
	endKey := traceKeyAt(cutoff)
	if err := s.pebble.DeleteRange(startKey, endKey, pebble.Sync); err != nil {
		logger.Default().LogError("pebble: prune failed", "error", err)
		return false
	}
	s.notePruned(cutoff)
	// DeleteRange only writes tombstones; compact the pruned range to actually
	// reclaim disk space instead of waiting for an opportunistic compaction.
	if err := s.pebble.Compact(startKey, endKey, true); err != nil {
		logger.Default().LogError("pebble: compaction failed", "error", err)
	}
	return true
}

// traceKeyAt is the store key every trace that started before t sorts below.
func traceKeyAt(t time.Time) []byte {
	return binary.BigEndian.AppendUint64(make([]byte, 0, 8), uint64(t.UnixNano()))
}

// budgetCheckEvery is how often the trace store's size is held to its budget.
const budgetCheckEvery = 30 * time.Second

// checkTraceBudget reads the free space now, and holds the store to its size
// budget when that is due -- off this goroutine, since the eviction compacts.
func (s *pathStatsStore) checkTraceBudget(now time.Time) {
	s.traceGuard.Check()
	if now.Before(s.nextBudgetCheck) {
		return
	}
	s.nextBudgetCheck = now.Add(budgetCheckEvery)
	s.wg.Go(s.enforceTraceBudget)
}

// enforceTraceBudget evicts the oldest traces, whatever their age, while the
// store takes more disk than its budget, bringing it to four fifths of it.
// It shares the prune's flag, so the two never compact at once.
//
// The trace archive's guard holds age-based pruning back until an hour is
// archived; the budget does not wait for it. A store that may not shrink
// until something else catches up is not bounded, and a disk filled by it
// takes the archive down too. Evicting an hour the archive has not taken is
// logged at WARN.
func (s *pathStatsStore) enforceTraceBudget() {
	if s.pruning.Swap(true) {
		return
	}
	defer s.pruning.Store(false)
	s.holdTraceBudget()
}

// holdTraceBudget is enforceTraceBudget's work, for a caller already holding
// the prune flag.
//
// What is held to the budget is the store's live tables: the traces
// themselves, which is what eviction can shrink. The write-ahead log and the
// files a compaction has just replaced come and go within a few memtables,
// and counting them would evict traces to pay for a moment's overhead.
func (s *pathStatsStore) holdTraceBudget() {
	budget := tracebudget.MaxBytes(config.CurrentTierDefaults())
	m := s.pebble.Metrics()
	tracebudget.ReportUsage(m.DiskSpaceUsage(), budget)
	tables := uint64(max(m.Total().Size, 0))
	if budget <= 0 || tables <= uint64(budget) {
		return
	}
	cutoff, ok := s.traceEvictionCutoff(tables - tracebudget.EvictionTarget(budget))
	if !ok {
		return
	}
	if held := guardTracePrune(cutoff); held.Before(cutoff) {
		logger.Default().LogWarn("trace store over its size budget: evicting traces the trace archive has not copied yet",
			"archived_through", held, "evicting_before", cutoff)
	}
	if s.deleteTracesBefore(cutoff) {
		after := s.pebble.Metrics()
		tracebudget.ReportUsage(after.DiskSpaceUsage(), budget)
		logger.Default().LogInfo("trace store over its size budget: oldest traces evicted",
			"evicted_before", cutoff, "bytes_before", tables, "bytes_after", after.Total().Size, "budget", budget)
	}
}

// traceEvictionCutoff is the time before which the stored traces take about
// need bytes on disk; false when there are no traces.
func (s *pathStatsStore) traceEvictionCutoff(need uint64) (time.Time, bool) {
	oldest, found, err := firstTraceTime(context.Background(), s.pebble.NewIter)
	if err != nil || !found {
		return time.Time{}, false
	}
	start := make([]byte, 8)
	below := func(t time.Time) uint64 {
		n, err := s.pebble.EstimateDiskUsage(start, traceKeyAt(t))
		if err != nil {
			return 0
		}
		return n
	}
	// A moment past now, so that "every trace" is a cutoff the search can reach.
	return tracebudget.FindCutoff(oldest, time.Now().Add(time.Millisecond), need, below), true
}

// TraceStoreNotReady is why the trace store is not writing, and "" while it
// is: /readyz reports it.
func TraceStoreNotReady() string {
	s := getStore()
	if s == nil {
		return ""
	}
	return s.traceGuard.Paused()
}

// prunedThroughFile keeps where the last trace prune stopped, among the trace
// store's own files -- Pebble passes over names it does not recognise -- so the
// hot floor survives a restart. Without it, until the first prune after a
// start, one trace written below the old prune point by a request that
// outlived retention would pull the floor down and hide the archived hours
// above it from a search.
const prunedThroughFile = "gateon-pruned-through"

func readPrunedThrough(dir string) int64 {
	b, err := os.ReadFile(filepath.Join(dir, prunedThroughFile)) // #nosec G304 -- the trace store's own directory and a fixed name
	if err != nil || len(b) != 8 {
		return 0
	}
	return int64(binary.BigEndian.Uint64(b))
}

// notePruned records that every trace before cutoff is gone, in memory and on
// disk. The disk copy is best effort: losing it costs only what it was kept
// to prevent, for the hour until the next prune writes it again.
func (s *pathStatsStore) notePruned(cutoff time.Time) {
	n := cutoff.UnixNano()
	if n <= s.tracesPrunedThrough.Load() {
		return
	}
	s.tracesPrunedThrough.Store(n)
	if s.traceDir == "" {
		return
	}
	tmp := filepath.Join(s.traceDir, prunedThroughFile+".tmp")
	if err := os.WriteFile(tmp, binary.BigEndian.AppendUint64(nil, uint64(n)), 0o600); err == nil {
		_ = os.Rename(tmp, filepath.Join(s.traceDir, prunedThroughFile))
	}
}

// traceCutoff is the time before which traces are past their retention. Zero
// means they are kept for good.
func (s *pathStatsStore) traceCutoff(now time.Time) time.Time {
	days := s.effectiveRetention(s.accessLogRetentionDays.Load())
	if days <= 0 {
		return time.Time{}
	}
	return now.AddDate(0, 0, -days)
}

// TracePruneGuard is consulted before traces are deleted for age. It is handed
// the retention cutoff and answers how far the deletion may go; an earlier
// answer holds traces back. It runs on the pruning goroutine, so it must answer
// from what it already knows rather than doing the work that would let it.
type TracePruneGuard func(cutoff time.Time) time.Time

var tracePruneGuard atomic.Pointer[TracePruneGuard]

// SetTracePruneGuard installs the guard, replacing any before it; nil removes it.
func SetTracePruneGuard(g TracePruneGuard) {
	if g == nil {
		tracePruneGuard.Store(nil)
		return
	}
	tracePruneGuard.Store(&g)
}

// guardTracePrune lets the installed guard hold traces back. It can only move
// the cutoff earlier: retention decides the most that may be deleted, and an
// answer past it is ignored rather than obeyed.
func guardTracePrune(cutoff time.Time) time.Time {
	g := tracePruneGuard.Load()
	if g == nil {
		return cutoff
	}
	if held := (*g)(cutoff); held.Before(cutoff) {
		return held
	}
	return cutoff
}

// TracePruneCutoff returns the time before which the next prune will delete
// traces, before any guard has its say. Zero means nothing is pruned.
func TracePruneCutoff(now time.Time) time.Time {
	s := getStore()
	if s == nil {
		return time.Time{}
	}
	return s.traceCutoff(now)
}

// pruneSecurityThreats removes recorded threats older than the retention window.
func (s *pathStatsStore) pruneSecurityThreats(ctx context.Context) {
	days := s.effectiveRetention(s.securityThreatRetentionDays.Load())
	if days <= 0 {
		return
	}
	cutoffTime := time.Now().AddDate(0, 0, -days)
	q := s.dialect.Rebind("DELETE FROM security_threats WHERE timestamp < ?")
	if _, err := s.db.ExecContext(ctx, q, cutoffTime); err != nil {
		logger.Default().LogError("security_threats: prune failed", "error", err)
	}
}

// pruneAuditLogs removes audit rows older than the configured window when audit
// retention is explicitly enabled.
func (s *pathStatsStore) pruneAuditLogs(ctx context.Context) {
	days := int(s.auditLogRetentionDays.Load())
	if days <= 0 {
		return
	}
	cutoffTime := time.Now().AddDate(0, 0, -days)
	q := s.dialect.Rebind("DELETE FROM audit_logs WHERE timestamp < ?")
	_, _ = s.db.ExecContext(ctx, q, cutoffTime)
}

// reclaimSQLDisk returns the space freed by the SQLite deletes back to the OS.
// It is a no-op for server databases (Postgres) which manage their own
// vacuuming. incremental_vacuum needs auto_vacuum=INCREMENTAL (set in
// SQLitePragmas); the WAL checkpoint truncates the write-ahead log file.
func (s *pathStatsStore) reclaimSQLDisk(ctx context.Context) {
	if s.dialect.Driver != db.DriverSQLite {
		return
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA incremental_vacuum;"); err != nil {
		logger.Default().LogError("sqlite: incremental_vacuum failed", "error", err)
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE);"); err != nil {
		logger.Default().LogError("sqlite: wal_checkpoint failed", "error", err)
	}
}

// ClosePathStatsStore stops background processing and closes the database.
func ClosePathStatsStore(ctx context.Context) error {
	storeMu.Lock()
	s := store
	if s == nil {
		storeMu.Unlock()
		return nil
	}
	store = nil
	storeMu.Unlock()

	if !s.stopped.Swap(true) {
		close(s.stopCh)
		c := make(chan struct{})
		go func() {
			s.wg.Wait()
			close(c)
		}()
		// Release a file creation held in the disk-full backoff, which the
		// loop's last flush or Pebble's close would otherwise wait out.
		s.traceGuard.Close()
		select {
		case <-c:
		case <-ctx.Done():
		}
		_ = s.pebble.Close()
		return s.db.Close()
	}
	return nil
}

// ConfigureRetention updates the retention days at runtime.
func ConfigureRetention(days int) {
	s := getStore()
	if s == nil {
		return
	}
	if days <= 0 {
		days = 1
	}
	s.retentionDays.Store(int32(days))
}

func ConfigureGranularRetention(pathStats, accessLog, securityThreat, auditLog int) {
	s := getStore()
	if s == nil {
		return
	}
	s.pathStatsRetentionDays.Store(int32(pathStats))
	s.accessLogRetentionDays.Store(int32(accessLog))
	s.securityThreatRetentionDays.Store(int32(securityThreat))
	s.auditLogRetentionDays.Store(int32(auditLog))
}

// recordToStore attempts to enqueue an increment; if the store is not initialized or channel is full, it drops silently to avoid impacting the hot path.
func recordToStore(host, path string, latencySeconds float64, bytesTotal uint64, at time.Time) {
	s := getStore()
	if s == nil {
		return
	}
	select {
	case s.inCh <- increment{host: host, path: path, latS: latencySeconds, bytesTotal: bytesTotal, atTime: at, isDomain: false}:
		// No need to update currentReqToday here as it's done in recordDomainToStore for total traffic
	default:
		// drop on backpressure to protect the request path
	}
}

// recordDomainToStore attempts to enqueue an increment for a domain.
func recordDomainToStore(domain string, latencySeconds float64, bytesTotal uint64, at time.Time) {
	s := getStore()
	if s == nil {
		return
	}
	select {
	case s.inCh <- increment{host: domain, latS: latencySeconds, bytesTotal: bytesTotal, atTime: at, isDomain: true}:
		s.currentReqToday.Add(1)
		s.currentBytesToday.Add(bytesTotal)
	default:
		// drop on backpressure
	}
}

func recordTraceToStore(tr *TraceRecord) {
	s := getStore()
	if s == nil || !s.traceStoreEnabled.Load() || tr == nil {
		if tr != nil {
			tr.Reset()
			tracePool.Put(tr)
		}
		return
	}

	select {
	case s.traceInCh <- tr:
	default:
		// drop on backpressure
		tr.Reset()
		tracePool.Put(tr)
	}
}

func (s *pathStatsStore) processTrace(tr *TraceRecord) {
	tr.ID = storableTraceID(tr.ID)

	// Format headers lazily in the background
	if tr.rawReqHeader != nil {
		tr.RequestHeaders = FormatHeaders(tr.rawReqHeader)
		tr.rawReqHeader = nil // Release map for GC
	}
	if tr.rawRespHeader != nil {
		tr.ResponseHeaders = FormatHeaders(tr.rawRespHeader)
		tr.rawRespHeader = nil // Release map for GC
	}

	// Every trace passes here before it is stored, and so before the
	// dashboard, the trace archive or a threat built from it can read it: the
	// one place its credentials are taken out (ADR 0060). Off the request path.
	tr.RequestHeaders = RedactHeaders(tr.RequestHeaders)
	tr.ResponseHeaders = RedactHeaders(tr.ResponseHeaders)
	tr.RequestURI = redact.URI(tr.RequestURI)
	tr.Referer = redact.URI(tr.Referer)
	tr.RequestBody = redact.Body(tr.RequestBody)
	tr.ResponseBody = redact.Body(tr.ResponseBody)
}

// RecordSecurityThreatWithJA4 is a helper that populates JA4 and JA4H from the request before recording.
func RecordSecurityThreatWithJA4(r *http.Request, t SecurityThreat) SecurityThreat {
	if rs := request.GetRequestState(r); rs != nil {
		if t.JA4 == "" {
			t.JA4 = rs.JA4
		}
		if t.JA4H == "" {
			t.JA4H = rs.JA4H
		}
		if t.Fingerprint == "" {
			t.Fingerprint = rs.JA4Plus
		}
	}
	if t.JA4 == "" {
		ja4 := JA4FromTrustedHeader(r)
		if ja4 == "" {
			// Try to get from context if request state is missing (unlikely in entrypoint but possible in tests)
			if ja4Val, ok := r.Context().Value(fingerprintCtxKey).(*ClientFingerprint); ok {
				ja4 = ja4Val.Hash
			}
		}
		t.JA4 = ja4
	}
	if t.JA4H == "" {
		t.JA4H = GetCachedJA4H(r)
	}
	if t.Fingerprint == "" {
		t.Fingerprint = t.JA4 + "_" + t.JA4H
	}

	// Capture raw headers for lazy formatting
	t.rawReqHeader = CloneHeader(r.Header)
	// Response headers are usually empty during threat recording (blocked early)
	// but we capture if present.
	return t
}

// RecordSecurityThreat attempts to enqueue a security threat.
func RecordSecurityThreat(t SecurityThreat) {
	st := GetSecurityThreat()
	*st = t
	// A threat from loopback is recorded, counted and shown -- and held
	// against nobody. It used to be dropped here, so a gateway behind a local
	// nginx or cloudflared with no trusted proxies (every client arrives as
	// 127.0.0.1) refused attacks while Security Hub said "0 threats" and the
	// funnel listed them as allowed (T27). It is still kept out of reputation,
	// escalation and correlation, as an unattributed threat is: loopback is
	// every local client at once, and the request path never refuses it.
	if httputil.IsLoopback(st.SourceIP) {
		st.Unattributed = true
	}
	if st.ID == "" {
		st.ID = uuid.NewString()
	}
	if st.Time.IsZero() {
		st.Time = time.Now()
	}

	s := getStore()
	if s == nil {
		st.Reset()
		threatPool.Put(st)
		return
	}

	select {
	case s.threatInCh <- st:
	default:
		// drop on backpressure
		st.Reset()
		threatPool.Put(st)
	}
}

const (
	// autoMitigateScore is the threat score at which the actor is mitigated
	// even though the request itself was allowed through.
	autoMitigateScore = 80

	// labelUnknown is the metric label used when a more specific value — a WAF
	// rule ID, a trap path — is not present on the threat. Prometheus labels
	// cannot be empty without creating a separate series.
	labelUnknown = "unknown"

	// typeBruteForce is the threat type recorded for repeated auth failures.
	typeBruteForce = "brute_force_attempt"
)

// normalizeThreatHeaders formats the captured headers and takes every
// credential out of the threat before anything persists, broadcasts, alerts,
// ships or correlates it (ADR 0060): header values, the query string of its
// request URI, its bodies, and its details. The raw maps are dropped so the
// pooled record does not hold request memory alive.
func normalizeThreatHeaders(st *SecurityThreat) {
	if st.rawReqHeader != nil {
		st.RequestHeaders = FormatHeaders(st.rawReqHeader)
		st.rawReqHeader = nil
	}
	if st.rawRespHeader != nil {
		st.ResponseHeaders = FormatHeaders(st.rawRespHeader)
		st.rawRespHeader = nil
	}
	st.RequestHeaders = RedactHeaders(st.RequestHeaders)
	st.ResponseHeaders = RedactHeaders(st.ResponseHeaders)
	// Details is redacted too: it frequently quotes the offending header back,
	// and sometimes the parameter.
	st.Details = redact.Text(RedactHeaders(st.Details))
	st.RequestURI = redact.URI(st.RequestURI)
	st.RequestBody = redact.Body(st.RequestBody)
	st.ResponseBody = redact.Body(st.ResponseBody)
}

// escalateMitigation blocks the actor behind a threat, not just the request.
//
// A fingerprint is blocked on the threat's network once that class has
// attacked from there repeatedly (escalateFingerprint, ADR 0026). The address
// itself is shunned only once more client classes have attacked from it than
// an office's few infected machines or misjudged browser builds produce
// (escalateAddress, ADR 0029): one address can front an entire office, and a
// shun refuses all of it until it lapses or an operator releases it.
//
// A threat not HeldAgainstSource is excluded: a mitigation or reputation
// refusal, or acting on one would produce another; a match nobody acted on;
// one the client did not choose to send.
//
// So is everything from an allowlisted source. Its threats are recorded,
// listed and correlated like any other -- the allowlist exempts enforcement,
// never observation -- but they are not evidence towards a block: a
// fingerprint block is kept for a build on a network and would refuse the
// source's neighbours who share its build, and evidence kept towards a shun
// would be held against the address the day it left the allowlist (ADR 0029).
func escalateMitigation(st *SecurityThreat) {
	if !st.Mitigated && st.Category != "reputation" && st.Score < autoMitigateScore {
		return
	}
	if !st.HeldAgainstSource() || mitigation.IsAllowlisted(st.SourceIP) {
		return
	}

	escalateFingerprint(st)
	escalateAddress(st)
}

// enrichThreatOrigin fills in geolocation and ASN when the caller did not.
func enrichThreatOrigin(st *SecurityThreat) {
	if st.SourceIP == "" {
		return
	}
	if st.CountryCode == "" {
		st.CountryCode, _, st.Latitude, st.Longitude = ResolveIPInfoFast(st.SourceIP)
	}
	if st.ASN == "" {
		st.ASN = ResolveASN(st.SourceIP)
	}
}

// recordMitigationFunnel attributes a stopped threat to the middleware that
// stopped it, so the security funnel adds up. Called only for threats that were
// actually mitigated; a detection with no action belongs in no funnel bucket.
// notifyThreat runs the registered alert hook and pushes the threat to live
// subscribers. The hook is read under the lock and called outside it, so a slow
// alerter cannot block whoever is registering one.
func notifyThreat(st *SecurityThreat) {
	alertMu.RLock()
	h := onThreatAlert
	alertMu.RUnlock()
	if h != nil {
		h(st)
	}
	ThreatBroadcaster.Broadcast(*st)
}

// funnelRule attributes a mitigated threat to the middleware that stopped it.
// Rules are evaluated in order and the first match wins, which preserves the
// precedence the original switch had — a WAF block that is also categorised
// "advanced" counts as WAF.
type funnelRule struct {
	matches func(cat, typ string) bool
	record  func(routeID, typ string, st *SecurityThreat)
}

// mitigationFunnelRules is a table rather than a switch so that adding a
// middleware means adding a row, and so the precedence above is something you
// can read top to bottom instead of inferring from case order.
var mitigationFunnelRules = []funnelRule{
	{
		matches: func(cat, typ string) bool {
			return cat == "waf" || typ == "waf_block" || typ == "waf_blocked" || typ == "waf_violation"
		},
		record: func(routeID, typ string, st *SecurityThreat) {
			// firstRuleID, not TriggeredRules. The label is declared rule_id
			// and its comment says rule ids come from a fixed ruleset, which
			// is true of one id and false of the *set*: TriggeredRules is the
			// JSON array of every rule the request matched, and an attacker
			// picks the combination by choosing which tokens to put in one
			// payload. One blocked request per novel combination, forever.
			MiddlewareWAFBlockedTotal.WithLabelValues(routeID, cmp.Or(firstRuleID(st.TriggeredRules), typ, labelUnknown)).Inc()
		},
	},
	{
		matches: func(_, typ string) bool { return strings.HasPrefix(typ, "fast_path_") },
		record: func(routeID, typ string, _ *SecurityThreat) {
			MiddlewareFastPathBlockedTotal.WithLabelValues(routeID, strings.TrimPrefix(typ, "fast_path_")).Inc()
		},
	},
	{
		matches: func(cat, typ string) bool { return typ == "rate_limit" || cat == "abuse" },
		record: func(routeID, _ string, _ *SecurityThreat) {
			MiddlewareRateLimitRejectedTotal.WithLabelValues(routeID, "behavioral").Inc()
		},
	},
	{
		matches: func(cat, typ string) bool {
			return cat == "deception" || typ == "honeypot_triggered" || typ == "honeypot_hit"
		},
		record: func(routeID, typ string, st *SecurityThreat) {
			// The label is declared trap_type, but RequestURI is the full
			// request path, and the honeypot matches by prefix -- so
			// /.git/<anything> qualifies and every suffix was its own series.
			// The trap that fired is the bounded thing worth recording.
			MiddlewareDeceptionBlockedTotal.WithLabelValues(routeID, cmp.Or(typ, labelUnknown)).Inc()
		},
	},
	{
		matches: func(cat, typ string) bool {
			return typ == "reputation_hit" || typ == "advanced_security" ||
				cat == "advanced" || cat == "threat_intel" ||
				typ == "ip_mitigation" || typ == "user_mitigation"
		},
		record: func(routeID, typ string, _ *SecurityThreat) {
			MiddlewareAdvancedSecurityBlockedTotal.WithLabelValues(routeID, typ).Inc()
		},
	},
	{
		matches: func(cat, _ string) bool { return cat == "geoip" || cat == "geofencing" },
		record: func(routeID, _ string, st *SecurityThreat) {
			MiddlewareGeoIPBlockedTotal.WithLabelValues(routeID, st.CountryCode).Inc()
		},
	},
	{
		matches: func(cat, typ string) bool { return cat == "auth" || typ == typeBruteForce },
		record: func(routeID, typ string, _ *SecurityThreat) {
			MiddlewareAuthFailuresTotal.WithLabelValues(routeID, typ).Inc()
		},
	},
	{
		matches: func(cat, _ string) bool { return cat == "bot" },
		record: func(routeID, _ string, _ *SecurityThreat) {
			MiddlewareBotManagementTotal.WithLabelValues(routeID, ActionBlocked).Inc()
		},
	},
	{
		matches: func(cat, _ string) bool { return cat == "filesecurity" || cat == "malware" },
		record: func(routeID, typ string, _ *SecurityThreat) {
			MiddlewareFileSecurityBlockedTotal.WithLabelValues(routeID, typ).Inc()
		},
	},
}

// firstRuleID reduces a TriggeredRules JSON array to its first element, so a
// metric label carries one rule id rather than an attacker-chosen combination
// of them. Anything it cannot parse becomes "" and the caller falls back.
func firstRuleID(triggered string) string {
	if triggered == "" {
		return ""
	}
	var ids []string
	if err := json.Unmarshal([]byte(triggered), &ids); err != nil || len(ids) == 0 {
		return ""
	}
	return ids[0]
}

func recordMitigationFunnel(st *SecurityThreat) {
	routeID := cmp.Or(st.RouteID, "global")
	cat := strings.ToLower(st.Category)
	typ := strings.ToLower(st.Type)

	for _, rule := range mitigationFunnelRules {
		if rule.matches(cat, typ) {
			rule.record(routeID, typ, st)
			return
		}
	}
}

func (s *pathStatsStore) processThreat(st *SecurityThreat) {
	normalizeThreatHeaders(st)

	if st.ActionTaken == "" {
		st.ActionTaken = ActionDetected
	}
	st.Mitigated = isMitigatingAction(st.ActionTaken)
	escalateMitigation(st)
	enrichThreatOrigin(st)

	// Log to audit trail
	audit.Log(context.Background(), "system", st.Type, st.RequestURI, fmt.Sprintf("Severity: %s, Details: %s, Action: %s", st.Severity, st.Details, st.ActionTaken), st.SourceIP)

	// Alerting and Broadcasting
	notifyThreat(st)

	isMitigated := st.Mitigated || isMitigatingAction(st.ActionTaken)
	// Funnel counters: which middleware actually stopped this.
	if isMitigated {
		recordMitigationFunnel(st)
	}
	// The per-address score the alerting manager's autonomous shun reads
	// (GetIPThreatScore). A threat not held against its source -- one a
	// control let through, among others -- is no evidence towards it either.
	if s.scoreCache != nil && st.HeldAgainstSource() {
		current, ok := s.scoreCache.Get(st.SourceIP)
		score := st.Score
		if ok {
			score += current.(float64)
		}
		s.scoreCache.Add(st.SourceIP, score)
	}

	// Scope the score to the network that earned it. Recording under the bare
	// fingerprint made one browser class share one score across every client
	// running it, which is what let a single attacker refuse everybody else --
	// see repid.For. The recording key and the enforcement key come from
	// the same function on purpose: if they ever diverge, every lookup returns
	// the neutral 100 and the control reports "clean" while checking nothing.
	// An allowlisted source's threats move no score (DecreaseReputationOf), and
	// neither does a threat not held against its source: an audit-only or
	// below-threshold match, a refusal of an earlier decision, or a leak in a
	// response the client was served (ADR 0055). The score is what the
	// reputation blocker refuses on, on every route.
	if st.HeldAgainstSource() {
		DecreaseReputationOf(st.Fingerprint, st.SourceIP, st.Score/2, st.Type) // Penalty is half the threat score
	}

	// Update global telemetry structures
	GlobalCMS.AddWeighted("global", uint32(st.Score))
	if st.SourceIP != "" {
		GlobalHHH.Add(st.SourceIP)
	}

	// Legacy global counters (per category/severity)
	if isMitigated {
		MitigatedThreatsTotal.WithLabelValues(cmp.Or(st.Category, "general"), cmp.Or(st.Severity, "medium"), cmp.Or(st.ActionTaken, "blocked")).Inc()
		s.currentMitigatedToday.Add(1)
	} else {
		ActiveThreatsTotal.WithLabelValues(cmp.Or(st.Category, "general"), cmp.Or(st.Severity, "medium")).Inc()
		s.currentActiveToday.Add(1)
	}
}

// GetIPThreatScore returns the current security threat score for an IP.
func GetIPThreatScore(ip string) float64 {
	s := getStore()
	if s == nil || s.scoreCache == nil {
		return 0
	}
	if val, ok := s.scoreCache.Get(ip); ok {
		return val.(float64)
	}
	return 0
}

// IsIPUnmitigated reports whether an operator released ip within the release
// hold (ipReleaseHold): what every automatic shun path respects before it
// shuns. A release used to exempt an address from them for good; now that an
// automatic shun lapses on its own, a release is a ruling on the shun in
// front of the operator, held for a day as a fingerprint release is (ADR
// 0031). Off the request path.
func IsIPUnmitigated(ip string) bool {
	s := getStore()
	if s == nil {
		return false
	}
	// Only a cached shun in force answers without the database: the cache
	// holds "not shunned" for every address IPMitigation looked up and found
	// no row for, which says nothing about a release.
	if s.unmitigatedCache != nil {
		if val, ok := s.unmitigatedCache.Get(addressCacheKey(ip)); ok {
			if until, isUntil := val.(shunUntil); isUntil && until.active() {
				return false
			}
		}
	}
	row, err := s.readIPShun(repid.AddressKey(ip))
	return err == nil && row.held(time.Now())
}

// IsIPMitigated is IsIPMitigatedContext for a caller with no context of its
// own -- the TCP accept path, the detectors -- which waits no longer than the
// lookup's deadline.
func IsIPMitigated(ip string) bool {
	return IsIPMitigatedContext(context.Background(), ip)
}

// IsIPMitigatedContext reports whether ip is shunned now: an operator's block,
// or an automatic shun that has not lapsed. A lapsed shun is lifted from the
// moment it lapses, with no sweeper involved: the cache keeps when the shun
// ends, not that there is one. It runs for every request IPMitigation sees and
// every connection a TCP entrypoint accepts.
//
// A shun in force is cached until it ends. "Not shunned" is answered from the
// cache for one to two mitigationEpochLength (ADR 0043); after that, for up to
// staleAnswerEpochs, the request is still answered from the cache and the
// address is read again in the background (ADR 0054), so a client the cache
// knows never waits for the database. Past that it is read again before the
// request is decided.
//
// That read waits at most the lookup deadline, or until ctx ends, and a
// lookup that fails or times out is never cached. The request it was for is
// served, unless the cache already holds a shun in force for the address:
// during a database outage the data plane keeps serving, and refusing every
// address the cache cannot vouch for would turn the outage into a total one --
// one a client can provoke wherever load alone produces SQLITE_BUSY. Blocks
// this node has seen stay enforced, from the cache; a block it has not seen
// since its last start is enforced from the first lookup after the database
// is back. The failures are counted in gateon_mitigation_lookup_errors_total.
func IsIPMitigatedContext(ctx context.Context, ip string) bool {
	s := getStore()
	if s == nil {
		return false
	}
	if blocked, ok := s.cachedIPMitigation(ip); ok {
		return blocked
	}
	until, err := s.lookups.ip.Do(ctx, repid.AddressKey(ip))
	if err != nil {
		mitigationLookupFailed(mitigationLookupIP, err)
		return false
	}
	return until.active()
}

// IPMitigationFromCache is IsIPMitigatedContext without the database: whether
// ip is shunned, and whether the cache could say. It never waits; an answer
// that is stale still answers, and is read again in the background. A caller
// with a cheaper decision of its own to make before the database is asked --
// the exemption, in identity.AddressBlocked -- asks this first, so the
// requests the cache answers, nearly all of them, pay for neither.
func IPMitigationFromCache(ip string) (blocked, ok bool) {
	s := getStore()
	if s == nil {
		return false, true
	}
	return s.cachedIPMitigation(ip)
}

func (s *pathStatsStore) cachedIPMitigation(ip string) (blocked, ok bool) {
	age := answerNone
	if s.unmitigatedCache != nil {
		if val, hit := s.unmitigatedCache.Get(addressCacheKey(ip)); hit {
			blocked, age = cachedIPAnswer(val)
		}
	}
	switch {
	case age == answerFresh:
		return blocked, true
	case !blocked && s.listedIPBlock(ip):
		// The block list holds a shun the cache does not know of: one read
		// before a restart, or written on another node since this answer
		// (ADR 0058). Enforced without a lookup, whether or not one could run.
		return true, true
	case age == answerStale:
		s.lookups.ip.Refresh(repid.AddressKey(ip))
		return blocked, true
	}
	return false, false
}

// addressCacheKey is what the enforcement cache keeps ip's answer under:
// repid.Address's key, in a form the request path builds without formatting
// text -- plain IPv4 text as it is, and an IPv6 address as the netip.Addr of
// its /64, which costs a parse and the one allocation the cache's interface
// key cost already (ADR 0058). A v4-mapped address is its IPv4 text.
func addressCacheKey(ip string) any {
	if strings.IndexByte(ip, ':') < 0 {
		return ip
	}
	a, ok := repid.Address(ip)
	switch {
	case !ok:
		return ip
	case a.Is4():
		return a.String()
	}
	return a
}

// cachedIPAnswer reads what the cache holds for an address: whether it is
// shunned, and how far the answer may be used without asking the database. A
// shun in force is fresh until it ends; a shun that has lapsed, and anything
// that is not an answer, is read again before the request is decided.
// Comma-ok: a bare assertion here panics on the request path.
func cachedIPAnswer(val any) (blocked bool, age answerAge) {
	switch v := val.(type) {
	case shunUntil:
		if v.active() {
			return true, answerFresh
		}
	case notBlockedUntil:
		return false, epochAge(int64(v))
	}
	return false, answerNone
}

// ipAnswerToCache is what the cache keeps for a shun read from the database:
// the shun while it is in force, and otherwise a bounded "not shunned".
func ipAnswerToCache(until shunUntil) any {
	if until.active() {
		return until
	}
	return notBlocked()
}

// lookupIPShun is the IP gate's read: ip's shun, cached when the database
// answered.
func (s *pathStatsStore) lookupIPShun(ctx context.Context, ip string) (shunUntil, error) {
	since := s.lookups.writes.Load()
	until, err := s.readIPShunUntil(ctx, ip)
	if err == nil {
		s.lookups.keep(s.unmitigatedCache, addressCacheKey(ip), ipAnswerToCache(until), since)
	}
	return until, err
}

// readIPShunUntil is ip's shun as enforcement needs it: the status and the
// end, and nothing else, so a timestamp written by an older version that does
// not scan cannot turn a block off. If the end does not scan, the status
// decides alone, as it did before shuns lapsed: a block stays a block. An
// error is returned only when neither read succeeds; it is not an answer.
func (s *pathStatsStore) readIPShunUntil(ctx context.Context, ip string) (shunUntil, error) {
	database := s.lookups.db.Load()
	var r ipShunRow
	err := database.QueryRowContext(ctx, s.lookups.queryIPEnd, ip).Scan(&r.status, &r.expiresAt)
	switch {
	case err == nil:
		return r.until(), nil
	case errors.Is(err, sql.ErrNoRows):
		return shunNone, nil
	}
	var status string
	statusErr := database.QueryRowContext(ctx, s.lookups.queryIPStatus, ip).Scan(&status)
	switch {
	case statusErr == nil && status == statusMitigated:
		return shunForever, nil
	case statusErr == nil, errors.Is(statusErr, sql.ErrNoRows):
		return shunNone, nil
	}
	return shunNone, errors.Join(err, statusErr)
}

// A "not blocked" answer -- for an address or a fingerprint -- and a
// fingerprint block are trusted for the epoch they were read in and the one
// after, then read again: between one and two mitigationEpochLength. That
// bounds how long a block written by another node, or straight to the
// database, goes unenforced here -- and a release, for a fingerprint block --
// at one indexed point read per active client per minute or two. The epoch is
// an atomic dailyResetLoop advances, so the answer nearly every request gets
// reads no clock. Not a tunable: shorter buys little, and longer is the
// staleness this replaces, which had no bound at all.
const mitigationEpochLength = time.Minute

// staleAnswerEpochs is how many epochs old an answer may be and still decide
// a request while it is read again in the background (ADR 0054): a client
// active in the last ten minutes never waits for the database. One gone for
// longer is read before its request is decided -- it has had time to earn a
// block elsewhere, and its first request is the one that should meet it.
const staleAnswerEpochs = 10

// mitigationEpoch counts mitigationEpochLength intervals since start.
var mitigationEpoch atomic.Int64

// notBlockedUntil is a "not blocked" answer as the enforcement caches keep it:
// the mitigationEpoch it was read in.
type notBlockedUntil int64

// notBlocked is a "not blocked" answer read now.
func notBlocked() notBlockedUntil {
	return notBlockedUntil(mitigationEpoch.Load())
}

// blockedAt is a fingerprint block as the enforcement cache keeps it: the
// mitigationEpoch it was read, or written, in.
type blockedAt int64

// blockedNow is a fingerprint block read, or written, now.
func blockedNow() blockedAt {
	return blockedAt(mitigationEpoch.Load())
}

// answerAge is how a cached answer may be used.
type answerAge uint8

const (
	// answerNone: there is no answer to use; the request waits for a lookup.
	answerNone answerAge = iota
	// answerFresh: the answer decides the request.
	answerFresh
	// answerStale: the answer decides the request, and is read again in the
	// background.
	answerStale
)

// epochAge is how an answer read in epoch may be used now.
func epochAge(epoch int64) answerAge {
	switch d := mitigationEpoch.Load() - epoch; {
	case d <= 1:
		return answerFresh
	case d <= staleAnswerEpochs:
		return answerStale
	}
	return answerNone
}

// The kinds of enforcement lookup, as gateon_mitigation_lookup_errors_total
// labels them.
const (
	mitigationLookupIP   = "ip"
	mitigationLookupUser = "user"
)

// Why an enforcement lookup decided a request without the database, as
// gateon_mitigation_lookup_errors_total labels it under labelReason.
const (
	labelReason = "reason"

	lookupReasonError     = "error"
	lookupReasonTimeout   = "timeout"
	lookupReasonSaturated = "saturated"
)

// MitigationLookupErrorsTotal counts enforcement lookups that could not read
// the database, by kind ("ip" or "user") and reason: "error" (the database
// refused), "timeout" (it did not answer within the lookup deadline) or
// "saturated" (every lookup slot was held, so none was started). Each is a
// request decided without it; see IsIPMitigatedContext.
var MitigationLookupErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_mitigation_lookup_errors_total",
	Help: "Address and fingerprint block lookups that could not read the database, by reason (error, timeout, saturated); the request was decided from the cache alone.",
}, []string{"kind", labelReason})

// lastLookupErrorLog is when a failed lookup was last logged, in Unix
// nanoseconds: an outage fails every lookup, and one line a minute says so.
var lastLookupErrorLog atomic.Int64

func mitigationLookupFailed(kind string, err error) {
	reason := lookupReasonError
	switch {
	case errors.Is(err, lookupgate.ErrTimeout):
		reason = lookupReasonTimeout
	case errors.Is(err, lookupgate.ErrSaturated):
		reason = lookupReasonSaturated
	}
	MitigationLookupErrorsTotal.WithLabelValues(kind, reason).Inc()
	now := time.Now().UnixNano()
	last := lastLookupErrorLog.Load()
	if now-last < int64(time.Minute) || !lastLookupErrorLog.CompareAndSwap(last, now) {
		return
	}
	logger.Default().LogError("block lookup failed; deciding requests from the cache until the database answers",
		"kind", kind, labelReason, reason, "error", err)
}

// Automatic shuns lapse (ADR 0031). A shun refuses everyone behind an address
// -- an office, a campus, a carrier's NAT pool -- on every route, so a
// mistaken one must cost minutes, not however long an operator takes to find
// it. A shunned address cannot be watched while it is shunned: the kernel or
// IPMitigation refuses its traffic before any detector sees it, and the
// refusals are marked so no detector counts them (request.RefusalMitigation).
// So a shun is not renewed from inside. It lapses, and an address that
// attacks again soon after is shunned again for twice as long, up to a day.
const (
	// autoShunBase is the first shun. Longer than mitigationEvidenceWindow,
	// so the evidence that earned it has aged out when it lapses and another
	// needs new evidence; the honeypot's first rung.
	autoShunBase = 15 * time.Minute
	// autoShunCap is the longest. Past a day an address is about as likely to
	// have been handed to someone else as to be the same client; the
	// honeypot's top rung and the fingerprint release's hold.
	autoShunCap = 24 * time.Hour
	// autoShunMemory is how long after a shun lapsed another counts as a
	// repeat; after a clean day the ladder starts again at autoShunBase.
	autoShunMemory = 24 * time.Hour
	// ipReleaseHold is how long an operator's release keeps every automatic
	// path off an address: the fingerprint release's hold.
	ipReleaseHold = unmitigationHoldWindow
)

// shunUntil is an address's shun as the enforcement cache keeps it: shunNone,
// shunForever (an operator's block), or when an automatic shun lapses, in Unix
// nanoseconds.
type shunUntil int64

const (
	shunNone    shunUntil = 0
	shunForever shunUntil = -1
)

// active reports whether the shun is in force, reading the clock only for one
// that lapses: an address with no shun costs a comparison.
func (u shunUntil) active() bool {
	switch u {
	case shunNone:
		return false
	case shunForever:
		return true
	}
	return time.Now().UnixNano() < int64(u)
}

// ipShunRow is an address's ip_mitigations row as the shun decisions read it.
type ipShunRow struct {
	status                                string
	mitigatedAt, expiresAt, unmitigatedAt sql.NullTime
}

// readIPShun reads ip's row: sql.ErrNoRows when it has none.
func (s *pathStatsStore) readIPShun(ip string) (ipShunRow, error) {
	var r ipShunRow
	err := s.db.QueryRow(s.dialect.Rebind(QueryReadIPShun), ip).Scan(&r.status, &r.mitigatedAt, &r.expiresAt, &r.unmitigatedAt)
	return r, err
}

// until is the row's shun as the cache keeps it. A lapsed shun keeps its
// (past) end, which reads as not in force.
func (r ipShunRow) until() shunUntil {
	switch {
	case r.status != statusMitigated:
		return shunNone
	case !r.expiresAt.Valid:
		return shunForever
	}
	return shunUntil(max(1, r.expiresAt.Time.UnixNano()))
}

// inForceAt reports whether the row's shun is in force at now.
func (r ipShunRow) inForceAt(now time.Time) bool {
	return r.status == statusMitigated && (!r.expiresAt.Valid || r.expiresAt.Time.After(now))
}

// held reports whether the row is an operator's release inside ipReleaseHold.
func (r ipShunRow) held(now time.Time) bool {
	return r.status == statusUnmitigated && r.unmitigatedAt.Valid && now.Sub(r.unmitigatedAt.Time) < ipReleaseHold
}

// nextShunDuration is how long an automatic shun written now lasts:
// autoShunBase, or twice as long as the last automatic shun lasted, up to
// autoShunCap, when that one lapsed less than autoShunMemory ago. A release
// resets the ladder, since the row then reads unmitigated.
func (r ipShunRow) nextShunDuration(now time.Time) time.Duration {
	if r.status != statusMitigated || !r.expiresAt.Valid || !r.mitigatedAt.Valid ||
		now.Sub(r.expiresAt.Time) >= autoShunMemory {
		return autoShunBase
	}
	last := r.expiresAt.Time.Sub(r.mitigatedAt.Time)
	return min(autoShunCap, max(autoShunBase, 2*last))
}

// ShunOutcome is what ShunAutomatically did.
type ShunOutcome int

const (
	// ShunApplied: the address is shunned until ShunResult.Until.
	ShunApplied ShunOutcome = iota + 1
	// ShunAlreadyInForce: an operator's block, or an automatic shun that has
	// not lapsed, already refuses the address; nothing changed.
	ShunAlreadyInForce
	// ShunExempt: loopback, on GATEON_MITIGATION_ALLOWLIST, or released by an
	// operator within ipReleaseHold. Not shunned.
	ShunExempt
)

// ShunResult is ShunAutomatically's answer.
type ShunResult struct {
	Outcome ShunOutcome
	Until   time.Time // when a ShunApplied shun lapses
}

// Shunned reports whether the address is refused after the call.
func (r ShunResult) Shunned() bool {
	return r.Outcome == ShunApplied || r.Outcome == ShunAlreadyInForce
}

// ShunAutomatically is how every automatic path shuns an address -- the
// address shun of ADR 0029, the anomaly detector, alert playbooks, the
// incident responder: for autoShunBase, or twice the last shun's length up to
// autoShunCap when the address comes back within autoShunMemory of its last
// shun lapsing (nextShunDuration). The shun is written with its expiry,
// enforced by IsIPMitigated until then and not after, and leased in the kernel
// to lapse with it.
//
// An address already shunned is left alone: a repeat while a shun is in force
// does not extend or escalate it, since nothing the address does while
// shunned can be observed. Loopback, the allowlist and an operator's release
// inside ipReleaseHold are exempt; an operator's own block (MarkIPMitigated)
// holds until released and is never shortened by this.
func ShunAutomatically(ip, reason string) (ShunResult, error) {
	s := getStore()
	if s == nil {
		return ShunResult{}, errNoTelemetryStore
	}
	if ip == "" || mitigation.ExemptFromEnforcement(ip) {
		// The same rule the kernel Holder and the data paths apply (ADR 0035):
		// loopback and an allowlisted address are never shunned automatically,
		// and evidence is not kept against them for the day they leave the list.
		return ShunResult{Outcome: ShunExempt}, nil
	}
	now := time.Now().UTC().Truncate(time.Second)
	prev, err := s.readIPShun(repid.AddressKey(ip))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ShunResult{}, err
	}
	switch {
	case prev.inForceAt(now):
		return ShunResult{Outcome: ShunAlreadyInForce}, nil
	case prev.held(now):
		return ShunResult{Outcome: ShunExempt}, nil
	}
	return s.applyAutoShun(ip, reason, now, now.Add(prev.nextShunDuration(now)))
}

// applyAutoShun writes ip's automatic shun until then and makes it take
// effect: the cache the request path reads, and a leased kernel entry.
func (s *pathStatsStore) applyAutoShun(ip, reason string, now, until time.Time) (ShunResult, error) {
	written, err := s.writeAutoShun(repid.AddressKey(ip), reason, now, until)
	if err != nil {
		logger.Default().LogError("failed to record an automatic shun", "ip", ip, "error", err)
		return ShunResult{}, err
	}
	if !written {
		// Another writer shunned or released it between the read and the
		// write; the row says which.
		if IsIPMitigated(ip) {
			return ShunResult{Outcome: ShunAlreadyInForce}, nil
		}
		return ShunResult{Outcome: ShunExempt}, nil
	}
	s.lookups.noteWrite()
	if s.unmitigatedCache != nil {
		s.unmitigatedCache.Add(addressCacheKey(ip), shunUntil(until.UnixNano()))
	}
	s.noteIPBlock(ip, until.UnixNano())
	// An automatic shun -- an SSH brute-forcer, a scanner -- reaches open L4
	// sessions too, not only connections accepted after it (ADR 0036).
	// ShunAutomatically already refused loopback and the allowlist, so the
	// address here is never exempt.
	fireIPBlocked(ip)
	shunInKernelUntil(ip, until)
	return ShunResult{Outcome: ShunApplied, Until: until}, nil
}

// writeAutoShun writes an automatic shun of ip from now until then, unless by
// the time it lands the row holds a shun in force or a release inside the
// hold. The condition is in the statement, so a check-then-write race cannot
// shorten an operator's block or override a release. Reports whether it wrote.
func (s *pathStatsStore) writeAutoShun(ip, reason string, now, until time.Time) (bool, error) {
	at := sqlUTC(now)
	res, err := s.db.Exec(s.dialect.Rebind(QueryWriteAutoShun),
		ip, reason, at, sqlUTC(until), at, sqlUTC(now.Add(-ipReleaseHold)))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// timedShunner is an eBPF provider that can lease a kernel shun (ebpf.Holder).
type timedShunner interface {
	ShunIPUntil(ip string, until time.Time) error
}

// shunInKernelUntil puts an automatic shun in the kernel, leased to lapse with
// it. A provider that cannot lease one is left out: a kernel entry nothing
// lifts is the never-ending shun this replaced, and IPMitigation enforces the
// shun above the kernel either way.
func shunInKernelUntil(ip string, until time.Time) {
	container, ok := globalEbpfManager.Load().(*ebpfProviderContainer)
	if !ok || container == nil || container.p == nil {
		return
	}
	if timed, isTimed := container.p.(timedShunner); isTimed {
		_ = timed.ShunIPUntil(ip, until)
	}
}

// sqlUTC formats t as ip_mitigations times are written and compared: UTC, to
// the second, in the layout CURRENT_TIMESTAMP writes on SQLite, so a plain
// comparison orders them on both engines. Bound rather than left to the
// database, whose CURRENT_TIMESTAMP is the server's zone on Postgres.
func sqlUTC(t time.Time) string {
	return t.UTC().Format(threatTimestampLayout)
}

// MarkIPMitigated records that an IP has been mitigated.
// errNoTelemetryStore is returned when a mitigation is requested before the
// store exists. It is a real failure from the caller's side -- nothing was
// written -- and was previously indistinguishable from success.
var errNoTelemetryStore = errors.New("telemetry: store is not initialised")

// ipBlockHooks are notified the moment an address is added to the IP mitigation
// list -- manually (MarkIPMitigated) or automatically (applyAutoShun). An open
// L4 session has no request boundary at which a block would otherwise reach it,
// so a shunned address's SSH, database or mail session ran on until it ended;
// the entrypoint layer registers a hook that closes an address's open
// connections, so a block reaches sessions already open, not only ones accepted
// after it (ADR 0036).
//
// A hook must not block: it runs on the goroutine that wrote the block (an
// operator's API request, or the telemetry loop that auto-shuns), which the
// close does not, being bounded by one entrypoint's connection cap. Registered
// once at startup, read under a short lock and iterated without one.
var (
	ipBlockHooksMu sync.RWMutex
	ipBlockHooks   []func(ip string)
)

// RegisterIPBlockHook adds fn to the callbacks fired when an address is blocked.
// It is called at process startup; fn must not block the caller that wrote the
// block. A nil fn is ignored.
func RegisterIPBlockHook(fn func(ip string)) {
	if fn == nil {
		return
	}
	ipBlockHooksMu.Lock()
	ipBlockHooks = append(ipBlockHooks, fn)
	ipBlockHooksMu.Unlock()
}

// fireIPBlocked notifies every registered hook that ip is now on the list. The
// slice is copied out under the read lock so a hook cannot deadlock against a
// concurrent RegisterIPBlockHook, and so the hooks run without holding it.
func fireIPBlocked(ip string) {
	if ip == "" {
		return
	}
	ipBlockHooksMu.RLock()
	hooks := ipBlockHooks
	ipBlockHooksMu.RUnlock()
	for _, fn := range hooks {
		fn(ip)
	}
}

// MarkIPMitigated records an operator's block of an address: it holds until
// released, whatever shun the address had. Automatic paths shun through
// ShunAutomatically, whose shuns lapse (ADR 0031).
//
// It returns the write error rather than only logging it. MitigateThreat does
// a read-back afterwards -- which exists, as the note below says, precisely
// because these writes can fail silently -- but the four other call sites did
// not, and each of them reported success to the operator regardless. A block
// that did not persist, announced as "blocked via middleware and shunned at
// XDP level", is a security control the operator believes is on.
func MarkIPMitigated(ip string, reason string) error {
	return markIPMitigated(ip, reason, 0)
}

// MarkIPMitigatedFor records an operator's block that lapses on its own after
// duration, needing no operator to lift it -- as an automatic shun does (ADR
// 0037), but chosen by the operator rather than the ladder. A non-positive
// duration is MarkIPMitigated: a block that holds until released. Enforcement
// (IsIPMitigated) reads the expiry and lifts the block the moment it lapses;
// the kernel entry is leased to lapse with it.
func MarkIPMitigatedFor(ip string, reason string, duration time.Duration) error {
	return markIPMitigated(ip, reason, duration)
}

// markIPMitigated writes an operator's block of ip. With a positive duration it
// sets expires_at and the block lapses there; otherwise it holds until
// released. Both are unconditional operator actions that override whatever the
// row held (unlike the automatic shun's conditional write). It returns the
// write error rather than only logging it, so a caller can tell the operator
// the truth about a block that did not persist.
func markIPMitigated(ip string, reason string, duration time.Duration) error {
	s := getStore()
	if s == nil {
		return errNoTelemetryStore
	}
	// Truncate now to the second as the automatic path does, so the cached end
	// (Unix nanoseconds) and the stored end (a second-resolution UTC string)
	// name the same instant.
	now := time.Now().UTC().Truncate(time.Second)
	cacheEnd := shunForever
	key := repid.AddressKey(ip)
	var err error
	if duration > 0 {
		until := now.Add(duration)
		cacheEnd = shunUntil(until.UnixNano())
		_, err = s.db.Exec(s.dialect.Rebind(QueryMarkIPMitigatedFor), key, reason, sqlUTC(now), sqlUTC(until))
	} else {
		_, err = s.db.Exec(s.dialect.Rebind(QueryMarkIPMitigated), key, reason, sqlUTC(now))
	}
	if err != nil {
		logger.Default().LogError("failed to mark IP as mitigated", "ip", ip, "error", err)
	}

	// Seeded only on success. This used to run unconditionally, and
	// IsIPMitigated reads the cache before the database -- so MitigateThreat's
	// read-back verification, which exists precisely because these writes can
	// fail silently, was answering from what the failed writer had just told
	// it. The operator saw "successfully mitigated" for a block that existed
	// nowhere but in a bounded ARC cache, and vanished on eviction or restart.
	//
	// On failure the cache is left alone, so IsIPMitigated falls through to
	// the database, finds nothing, and the verification reports the truth.
	if err == nil {
		s.lookups.noteWrite()
	}
	if err == nil && s.unmitigatedCache != nil {
		s.unmitigatedCache.Add(addressCacheKey(ip), cacheEnd)
	}
	if err == nil {
		s.noteIPBlock(ip, int64(cacheEnd))
	}

	// A block reaches the entrypoints' open sessions, not only connections
	// accepted after it. Fired only on a successful write, after the cache is
	// seeded so a hook that re-reads the list sees the block. The hook honours
	// the same exemption the accept-time check does, so an allowlisted address
	// an operator also blocked is not cut (ADR 0036).
	if err == nil {
		fireIPBlocked(ip)
	}

	// Real-time eBPF synchronization for immediate effect at XDP layer. A
	// bounded block leases the kernel entry so it lapses with the block, as an
	// automatic shun does; an open-ended block holds until released.
	markIPMitigatedInKernel(ip, now, duration)
	return err
}

// markIPMitigatedInKernel pushes an operator's block to the kernel shun map: a
// lease that lapses with a bounded block, or an unleased entry for one that
// holds until released. The push is gated by the kernel's own exemption, so an
// allowlisted or loopback address is not dropped in the kernel (ADR 0035).
func markIPMitigatedInKernel(ip string, now time.Time, duration time.Duration) {
	if duration > 0 {
		shunInKernelUntil(ip, now.Add(duration))
		return
	}
	if val := globalEbpfManager.Load(); val != nil {
		if container, ok := val.(*ebpfProviderContainer); ok && container.p != nil {
			_ = container.p.ShunIP(ip)
		}
	}
}

// MarkIPUnmitigated records an operator's release of an address: its shun
// ends now, and no automatic path shuns it again for ipReleaseHold.
//
// Returns the write error for the same reason MarkIPMitigated does: the two
// callers both answered "removed successfully" whatever happened, and the note
// below already describes that outcome for the cache half of it.
func MarkIPUnmitigated(ip string) error {
	s := getStore()
	if s == nil {
		return errNoTelemetryStore
	}
	// The release time is bound in UTC rather than taken from the database's
	// CURRENT_TIMESTAMP, which Postgres writes in the server's zone into a
	// column without one: the hold is measured from it.
	key := repid.AddressKey(ip)
	_, err := s.db.Exec(s.dialect.Rebind(QueryReleaseIPMitigation), sqlUTC(time.Now()), key)
	if err != nil {
		logger.Default().LogError("failed to mark IP as unmitigated", "ip", ip, "error", err)
	}

	// Same reasoning as MarkIPMitigated, mirrored. A release that failed to
	// persist used to seed the cache anyway, so the API answered "removed
	// successfully" while the row still said mitigated -- and once the cache
	// entry was evicted the block came back on its own.
	if err == nil {
		s.lookups.noteWrite()
	}
	if err == nil && s.unmitigatedCache != nil {
		s.unmitigatedCache.Add(addressCacheKey(ip), notBlocked())
	}
	if err == nil {
		s.noteIPBlock(ip, blocklist.Released)
	}
	// A release is a ruling on the evidence that earned the shun, so none of
	// it may count towards another (ADR 0029).
	if err == nil {
		forgetAddressEvidence(key)
	}

	// Real-time eBPF synchronization to restore access immediately
	if val := globalEbpfManager.Load(); val != nil {
		if container, ok := val.(*ebpfProviderContainer); ok && container.p != nil {
			// ONLY unshun if it's a valid IP.
			if net.ParseIP(ip) != nil {
				_ = container.p.UnshunIP(ip)
			}
		}
	}
	return err
}

// GetMitigatedIPs returns the addresses shunned now (plain strings).
func GetMitigatedIPs(ctx context.Context) []string {
	s := getStore()
	if s == nil {
		return nil
	}
	query := s.dialect.Rebind(`SELECT ip FROM ip_mitigations WHERE ` + inForceIPMitigation)
	rows, err := s.db.QueryContext(ctx, query, sqlUTC(time.Now()))
	if err != nil {
		return nil
	}
	defer rows.Close()
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err == nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

// GetIPMitigations returns the address shuns in force, with when each
// automatic one lifts. A lapsed shun blocks nobody and is not listed or
// counted, from the moment it lapses.
func GetIPMitigations(ctx context.Context, limit, offset int) ([]IPMitigation, int) {
	s := getStore()
	if s == nil {
		return nil, 0
	}
	if limit <= 0 {
		limit = 50
	}

	now := sqlUTC(time.Now())
	var total int
	if err := s.db.QueryRowContext(ctx, s.dialect.Rebind(QueryCountInForceIPMitigations), now).Scan(&total); err != nil {
		return nil, 0
	}

	ex, cleanup := s.getExecutor(ctx)
	defer cleanup()

	rows, err := ex.QueryContext(ctx, s.dialect.Rebind(QueryListInForceIPMitigations), now, limit, offset)
	if err != nil {
		return nil, 0
	}
	defer rows.Close()

	var res []IPMitigation
	for rows.Next() {
		var m IPMitigation
		var mitigatedAt, updatedAt time.Time
		var unmitigatedAt, expiresAt sql.NullTime
		if err := rows.Scan(&m.IP, &m.Status, &m.Reason, &mitigatedAt, &unmitigatedAt, &updatedAt, &expiresAt); err == nil {
			m.MitigatedAt = mitigatedAt
			m.UpdatedAt = updatedAt
			if unmitigatedAt.Valid {
				m.UnmitigatedAt = &unmitigatedAt.Time
			}
			if expiresAt.Valid {
				m.ExpiresAt = &expiresAt.Time
			}
			res = append(res, m)
		}
	}
	return res, total
}

// IsUserMitigated is IsUserMitigatedContext for a caller with no context of
// its own, which waits no longer than the lookup's deadline.
func IsUserMitigated(ja4plus string) bool {
	return IsUserMitigatedContext(context.Background(), ja4plus)
}

// IsUserMitigatedContext reports whether a client class is blocked on a
// network: key is repid.For(fingerprint, address), the identity UserMitigation
// enforces (telemetry.GetReputationID). A key without a network scope -- a
// bare fingerprint, as blocks were keyed before ADR 0026 -- names a class on
// every network and is never enforced.
func IsUserMitigatedContext(ctx context.Context, ja4plus string) bool {
	s := getStore()
	if s == nil {
		return false
	}
	blocked, ok := s.cachedUserMitigation(ja4plus)
	if ok {
		return blocked
	}
	mitigated, err := s.lookups.user.Do(ctx, ja4plus)
	if err != nil {
		// Not cached, and not an answer: a block this node holds stays a
		// block, and anything else is decided for this request alone, as
		// IsIPMitigatedContext decides it.
		mitigationLookupFailed(mitigationLookupUser, err)
		return blocked
	}
	return mitigated
}

// UserMitigationFromCache is IsUserMitigatedContext without the database, as
// IPMitigationFromCache is for an address.
func UserMitigationFromCache(ja4plus string) (blocked, ok bool) {
	s := getStore()
	if s == nil {
		return false, true
	}
	return s.cachedUserMitigation(ja4plus)
}

// cachedUserMitigation answers a fingerprint key without the database when it
// can. When it cannot, blocked still says whether the cache held a block too
// old to decide, which a lookup that then fails keeps.
func (s *pathStatsStore) cachedUserMitigation(ja4plus string) (blocked, ok bool) {
	if !repid.Scoped(ja4plus) {
		return false, true
	}
	// 1. An operator's release on this node overrides (MarkUserUnmitigated).
	if s.unmitigatedCache != nil {
		if _, released := s.unmitigatedCache.Get(ja4plus); released {
			return false, true
		}
	}
	// 2. A cached answer -- block or "not blocked" -- decides for one to two
	// mitigationEpochLength, so a block or a release written on another node
	// takes effect here within that (ADR 0043); then, for up to
	// staleAnswerEpochs, it still decides while it is read again in the
	// background (ADR 0054). A cached block used to be read again on every
	// request, which put a database round trip on every request a blocked
	// client made (dataplane F7).
	blocked, age := s.cachedUserAnswer(ja4plus)
	switch {
	case age == answerFresh:
		return blocked, true
	case !blocked && s.blocks.HasKeys() && s.blocks.KeyBlocked(ja4plus):
		// 3. The block list holds a block the cache does not know of (ADR
		// 0058), enforced without a lookup.
		return true, true
	case age == answerStale:
		s.lookups.user.Refresh(ja4plus)
		return blocked, true
	}
	return blocked, false
}

// cachedUserAnswer reads what the cache holds for a fingerprint key, as
// cachedIPAnswer does for an address. A block too old to decide is still
// reported blocked, so a lookup that then fails keeps it.
func (s *pathStatsStore) cachedUserAnswer(key string) (blocked bool, age answerAge) {
	if s.userMitigationCache == nil {
		return false, answerNone
	}
	val, ok := s.userMitigationCache.Get(key)
	if !ok {
		return false, answerNone
	}
	switch v := val.(type) {
	case blockedAt:
		return true, epochAge(int64(v))
	case notBlockedUntil:
		return false, epochAge(int64(v))
	}
	return false, answerNone
}

// userAnswerToCache is what the cache keeps for a fingerprint lookup.
func userAnswerToCache(blocked bool) any {
	if blocked {
		return blockedNow()
	}
	return notBlocked()
}

// lookupUserBlock is the fingerprint gate's read: whether key is blocked,
// cached when the database answered.
func (s *pathStatsStore) lookupUserBlock(ctx context.Context, key string) (bool, error) {
	since := s.lookups.writes.Load()
	blocked, err := s.readUserMitigated(ctx, key)
	if err == nil {
		s.lookups.keep(s.userMitigationCache, key, userAnswerToCache(blocked), since)
	}
	return blocked, err
}

// readUserMitigated reads whether key is blocked; sql.ErrNoRows is "not
// blocked", any other error is no answer.
func (s *pathStatsStore) readUserMitigated(ctx context.Context, ja4plus string) (bool, error) {
	var status string
	err := s.lookups.db.Load().QueryRowContext(ctx, s.lookups.queryUser, ja4plus, ja4plus, mitigationCutoff()).Scan(&status)
	switch {
	case err == nil:
		return status == statusMitigated, nil
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	}
	return false, err
}

// queryReadUserMitigated reads a fingerprint key's latest decision inside the
// block TTL. Ties break towards "unmitigated", and that is the whole point of
// the second ORDER BY term.
//
// CURRENT_TIMESTAMP is second-granular on SQLite, and a release is normally
// applied within the same second as the block it undoes -- an operator
// clicking Remove Mitigation on a threat that just fired, or a test releasing
// what it just earned. With only updated_at to sort by, those two rows tie and
// the winner is whatever the storage engine returns first, so the release
// lands, reports success, and the client stays blocked.
//
// Breaking the tie the other way would mean a stale block outliving an
// explicit unblock, which is the failure an operator cannot diagnose and
// cannot work around.
const queryReadUserMitigated = `SELECT status FROM user_mitigations
		WHERE (fingerprint = ? OR ja4h = ?) AND updated_at > ?
		ORDER BY updated_at DESC, CASE status WHEN 'unmitigated' THEN 0 ELSE 1 END
		LIMIT 1`

// blockLookups runs the block lookups the request path waits for -- an
// address's shun and a fingerprint's block -- through lookupgate (ADR 0054):
// each waits at most the lookup deadline, concurrent lookups of one key share
// a query, and at most blockLookupSlots run at once across both kinds.
type blockLookups struct {
	// db is what the lookups read: the store's database, or the one a test
	// stands in (SetBlockLookupDBForTest).
	db    atomic.Pointer[sql.DB]
	slots *lookupgate.Slots
	ip    *lookupgate.Gate[shunUntil]
	user  *lookupgate.Gate[bool]
	// writes counts this node's writes to the block list and its releases. A
	// lookup that read the database before one of them must not leave its
	// answer cached over the write's (keep).
	writes atomic.Uint64
	// The lookup queries, rebound for the dialect once rather than per read.
	queryIPEnd, queryIPStatus, queryUser string
}

func newBlockLookups(s *pathStatsStore) *blockLookups {
	td := config.CurrentTierDefaults()
	l := &blockLookups{
		slots:         lookupgate.NewSlots(blockLookupSlots(td)),
		queryIPEnd:    s.dialect.Rebind(QueryReadIPShunEnd),
		queryIPStatus: s.dialect.Rebind(QueryReadIPShunStatus),
		queryUser:     s.dialect.Rebind(queryReadUserMitigated),
	}
	l.db.Store(s.db)
	timeout := blockLookupTimeout(td)
	l.ip = lookupgate.New(l.slots, timeout, s.lookupIPShun)
	l.user = lookupgate.New(l.slots, timeout, s.lookupUserBlock)
	return l
}

func (l *blockLookups) setTimeout(d time.Duration) {
	l.ip.SetTimeout(d)
	l.user.SetTimeout(d)
}

// noteWrite records a write to the block list or a release, before the write
// touches the cache.
func (l *blockLookups) noteWrite() { l.writes.Add(1) }

// keep caches a lookup's answer -- unless a block or a release was written on
// this node since the lookup began, which may have read the database before
// it. Then the entry is dropped rather than kept over the write's own, and the
// next request reads the database again. Rare: blocks are.
func (l *blockLookups) keep(c *lru.ARCCache, key, answer any, since uint64) {
	if c == nil {
		return
	}
	c.Add(key, answer)
	if l.writes.Load() != since {
		c.Remove(key)
	}
}

// BlockLookupTimeout is how long one block lookup waits for the database:
// what a request that has to look up waits at most (ADR 0054). Zero with no
// store open.
func BlockLookupTimeout() time.Duration {
	if s := getStore(); s != nil {
		return s.lookups.ip.Timeout()
	}
	return 0
}

// envBlockLookupTimeout overrides the tier's block lookup deadline
// (TierDefaults.BlockLookupTimeout), as a Go duration: "150ms".
const envBlockLookupTimeout = "GATEON_BLOCK_LOOKUP_TIMEOUT"

// blockLookupTimeout is the lookup deadline: GATEON_BLOCK_LOOKUP_TIMEOUT if it
// is a positive duration, else the tier's. Zero is not "no deadline": that is
// the defect the deadline removes.
func blockLookupTimeout(td config.TierDefaults) time.Duration {
	return envDuration(envBlockLookupTimeout, td.BlockLookupTimeout)
}

// blockLookupSlots is how many block lookups may be in flight at once: eight
// per connection in the tier's database pool -- minimal 40, standard 200,
// enterprise 800.
//
// The pool, not this, bounds what the lookups ask of the database: one past
// it waits for a connection inside database/sql, and that wait honours the
// lookup's deadline. So against a stopped server at most the pool's worth are
// stuck in a driver read, and the rest give up at the deadline and free their
// slot. What this bounds is goroutines and the gate's map, under a flood of
// new addresses. It is generous because a lookup refused a slot is decided
// without the database: half the pool -- two lookups on the minimal tier --
// left a burst of twenty new clients to a healthy database mostly unchecked
// (measured on Postgres, ADR 0054), while eight 1-2 ms reads queued on each
// connection clear well inside the deadline.
func blockLookupSlots(td config.TierDefaults) int {
	return 8 * max(1, td.DBMaxOpenConns)
}

// SetBlockLookupDBForTest points the block lookups at database until the
// returned func restores the store's own, so a test outside this package can
// stand a database that stops answering behind the request path
// (testutil.HangDB). It panics with no store open. Tests only.
func SetBlockLookupDBForTest(database *sql.DB) (restore func()) {
	s := getStore()
	if s == nil {
		panic("telemetry: SetBlockLookupDBForTest with no store open")
	}
	prev := s.lookups.db.Swap(database)
	return func() { s.lookups.db.Store(prev) }
}

// WaitBlockLookupsForTest returns once every block lookup started so far has
// ended -- after a test released the database it stood in. Tests only.
func WaitBlockLookupsForTest() {
	if s := getStore(); s != nil {
		s.lookups.ip.Wait()
		s.lookups.user.Wait()
	}
}

// The block list (ADR 0058): every block in force, read at start-up and every
// blockListRefreshEvery, so a block is enforced without a lookup -- after a
// restart, and while the lookups are saturated or the database does not
// answer -- which the cache, learning blocks one lookup at a time, could not.
const (
	// blockListRefreshEvery is how often the list is read again: the epoch a
	// cached answer is trusted for, so a block or release written on another
	// node reaches the list as soon as it reaches the cache.
	blockListRefreshEvery = mitigationEpochLength
	// blockListReadTimeout bounds one read where the driver honours it.
	blockListReadTimeout = 30 * time.Second
	// blockListStartWait is how long opening the store waits for the first
	// read. The database answered the migrations a moment before; one that
	// stops answering now does not hold start-up longer than this, and the
	// list is read on the next refresh.
	blockListStartWait = 5 * time.Second
)

// blockListBounds is what the list holds: 20,000 address shuns (an IPv4
// address or IPv6 /64 and an end; 1.3 MB at the bound, measured) and 20,000
// fingerprint blocks (a key of at most 128 bytes -- repid.For writes under 100
// -- and an end; 2.8 MB at the bound with keys of that length, about 3.7 MB
// with every key at 128): at most 5 MB for one read, and a refresh holds two
// reads for a moment. A list larger than that is read
// newest first and the rest is left to the lookups, as before the list
// existed (reported in gateon_mitigation_block_list_complete). Not a
// tunable: it is a bound on an attack's worth of blocks, not a size an
// operator chooses. A var so a test can make it small.
var blockListBounds = blocklist.Bounds{Entries: 20_000, KeyBytes: 128, Edits: 4_096}

var (
	// BlockListEntries is how many blocks the last read of the block list
	// holds, by kind ("ip" or "user").
	BlockListEntries = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "gateon_mitigation_block_list_entries",
		Help: "Blocks in force this node enforces without a database lookup, by kind (ip, user), as of the last read.",
	}, []string{"kind"})
	// BlockListComplete is 1 while the block list holds every block in force
	// of a kind, and 0 when there were more than blockListBounds.Entries: the
	// oldest are then enforced only by a lookup.
	BlockListComplete = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "gateon_mitigation_block_list_complete",
		Help: "1 if the block list holds every block in force of a kind (ip, user); 0 if some are enforced only by a database lookup.",
	}, []string{"kind"})
)

// blockListLoop reads the block list at once, closes loaded, and reads it
// again every blockListRefreshEvery until the store stops.
func (s *pathStatsStore) blockListLoop(loaded chan<- struct{}) {
	complete := s.readBlockList(true)
	close(loaded)
	ticker := time.NewTicker(blockListRefreshEvery)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			complete = s.readBlockList(complete)
		}
	}
}

// readBlockList reads every block in force into the list. A read that fails
// leaves the last one in force -- its automatic shuns still lapse when they
// end -- and is logged. It returns whether the list holds every block,
// logging when that changes from wasComplete.
func (s *pathStatsStore) readBlockList(wasComplete bool) bool {
	ctx, cancel := context.WithTimeout(context.Background(), blockListReadTimeout)
	defer cancel()
	t := s.blocks.Begin()
	b := s.blocks.NewBase()
	err := s.readIPShunsInto(ctx, b)
	if err == nil {
		err = s.readUserBlocksInto(ctx, b)
	}
	if err != nil {
		logger.Default().LogError("block list: read failed; enforcing the last list read", "error", err)
		return wasComplete
	}
	s.blocks.Replace(t, b)
	ips, keys, ipsComplete, keysComplete := s.blocks.Size()
	BlockListEntries.WithLabelValues(mitigationLookupIP).Set(float64(ips))
	BlockListEntries.WithLabelValues(mitigationLookupUser).Set(float64(keys))
	BlockListComplete.WithLabelValues(mitigationLookupIP).Set(boolGauge(ipsComplete))
	BlockListComplete.WithLabelValues(mitigationLookupUser).Set(boolGauge(keysComplete))
	complete := ipsComplete && keysComplete
	if wasComplete && !complete {
		logger.Default().LogWarn("block list: more blocks in force than it holds; the oldest are enforced only by a lookup",
			"bound", blockListBounds.Entries)
	}
	return complete
}

func boolGauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// readIPShunsInto adds every address shun in force to b, newest first. A row
// whose key is not an address, or whose end does not scan, is left to the
// lookup, which reads it as it always has.
func (s *pathStatsStore) readIPShunsInto(ctx context.Context, b *blocklist.Base) error {
	rows, err := s.db.QueryContext(ctx, s.dialect.Rebind(QueryBlockListIPShuns), sqlUTC(time.Now()), blockListBounds.Entries+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		var end sql.NullTime
		if rows.Scan(&ip, &end) != nil {
			b.AddressesCut()
			continue
		}
		a, ok := repid.Address(ip)
		if !ok {
			continue
		}
		until := blocklist.Forever
		if end.Valid {
			until = end.Time.UnixNano()
		}
		if !b.AddAddress(a, until) {
			break
		}
	}
	return rows.Err()
}

// readUserBlocksInto adds every fingerprint block in force to b: each scoped
// key whose latest row inside the TTL is a block, until that row's TTL ends.
func (s *pathStatsStore) readUserBlocksInto(ctx context.Context, b *blocklist.Base) error {
	limit := blockListBounds.Entries + 1
	rows, err := s.db.QueryContext(ctx, s.dialect.Rebind(QueryBlockListUserMitigations), mitigationCutoff(), limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	seen := make(map[string]struct{})
	n := 0
	for rows.Next() {
		n++
		var key, status string
		var at time.Time
		if rows.Scan(&key, &status, &at) != nil {
			b.KeysCut()
			continue
		}
		if _, decided := seen[key]; decided {
			continue
		}
		seen[key] = struct{}{}
		if status == statusMitigated && !b.AddKey(key, at.Add(mitigationTTL).UnixNano()) {
			break
		}
	}
	if n >= limit {
		b.KeysCut()
	}
	return rows.Err()
}

// awaitBlockList waits for the store's first read of the block list, at most
// blockListStartWait.
func (s *pathStatsStore) awaitBlockList() {
	timer := time.NewTimer(blockListStartWait)
	defer timer.Stop()
	select {
	case <-s.blockListLoaded:
	case <-timer.C:
		logger.Default().LogWarn("block list: not read within the start-up wait; blocks are enforced by lookup until it is",
			"wait", blockListStartWait)
	}
}

// listedIPBlock reports whether the block list holds a shun in force for ip.
// An empty list -- most installs, most of the time -- costs a load.
func (s *pathStatsStore) listedIPBlock(ip string) bool {
	if !s.blocks.HasAddresses() {
		return false
	}
	a, ok := repid.Address(ip)
	return ok && s.blocks.AddressBlocked(a)
}

// noteIPBlock records this node's write of ip's block (until its end) or
// release (blocklist.Released) in the block list.
func (s *pathStatsStore) noteIPBlock(ip string, until int64) {
	if a, ok := repid.Address(ip); ok {
		s.blocks.NoteAddress(a, until)
	}
}

// unmitigationHoldWindow is how long a manual release of a fingerprint holds
// before escalateMitigation may block it again.
const unmitigationHoldWindow = 24 * time.Hour

// IsUserUnmitigated returns true if the JA4+ fingerprint is currently explicitly unmitigated.
func IsUserUnmitigated(ja4plus string) bool {
	s := getStore()
	if s == nil || ja4plus == "" {
		return false
	}
	// The cutoff is bound as a parameter, the way IsUserMitigated binds its
	// own, rather than computed in SQL: the previous datetime('now', '-1 day')
	// is SQLite's and does not exist on Postgres, where the query errored and
	// the error read as "not released" -- so a fingerprint an operator had just
	// released was blocked again by the next threat it produced.
	cutoff := time.Now().UTC().Add(-unmitigationHoldWindow).Format(threatTimestampLayout)
	query := s.dialect.Rebind("SELECT status FROM user_mitigations WHERE status = 'unmitigated' AND (fingerprint = ? OR ja4h = ?) AND updated_at > ?")
	var status string
	err := s.db.QueryRow(query, ja4plus, ja4plus, cutoff).Scan(&status)
	return err == nil && status == statusUnmitigated
}

// GetUserMitigations returns the fingerprint blocks in force: a client class on
// a network each, inside its TTL. Rows past the TTL block nobody, and a row
// with no network scope was written before ADR 0026 and is never enforced, so
// neither is listed or counted as a mitigation.
func GetUserMitigations(ctx context.Context, limit, offset int) ([]UserMitigation, int) {
	s := getStore()
	if s == nil {
		return nil, 0
	}
	if limit <= 0 {
		limit = 50
	}

	cutoff := mitigationCutoff()
	var total int
	if err := s.db.QueryRowContext(ctx, s.dialect.Rebind(QueryCountInForceUserMitigations), cutoff).Scan(&total); err != nil {
		return nil, 0
	}

	query := s.dialect.Rebind(QueryListInForceUserMitigations)
	ex, cleanup := s.getExecutor(ctx)
	defer cleanup()

	rows, err := ex.QueryContext(ctx, query, cutoff, limit, offset)
	if err != nil {
		return nil, 0
	}
	defer rows.Close()

	var res []UserMitigation
	for rows.Next() {
		var m UserMitigation
		var mitigatedAt, updatedAt time.Time
		var unmitigatedAt sql.NullTime
		var category sql.NullString
		if err := rows.Scan(&m.Fingerprint, &m.JA4H, &m.Type, &m.Status, &m.Reason, &category, &mitigatedAt, &unmitigatedAt, &updatedAt); err == nil {
			m.MitigatedAt = mitigatedAt
			m.UpdatedAt = updatedAt
			m.Category = category.String
			if unmitigatedAt.Valid {
				m.UnmitigatedAt = &unmitigatedAt.Time
			}
			res = append(res, m)
		}
	}
	return res, total
}

// GetCombinedMitigations returns a unified list of both IP and User mitigations.
func GetCombinedMitigations(ctx context.Context, limit, offset int) ([]CombinedMitigation, int) {
	s := getStore()
	if s == nil {
		return nil, 0
	}
	if limit <= 0 {
		limit = 50
	}

	// Both halves are what is in force: the address shuns that have not
	// lapsed, as GetIPMitigations lists them, and the fingerprint blocks, as
	// GetUserMitigations does.
	now := sqlUTC(time.Now())
	cutoff := mitigationCutoff()
	var totalIP, totalUser int
	_ = s.db.QueryRowContext(ctx, s.dialect.Rebind(QueryCountInForceIPMitigations), now).Scan(&totalIP)
	_ = s.db.QueryRowContext(ctx, s.dialect.Rebind(QueryCountInForceUserMitigations), cutoff).Scan(&totalUser)
	total := totalIP + totalUser

	// Use UNION ALL for consistent paging across both types.
	// Cast nulls to empty strings for consistency in scans.
	query := `
		SELECT 'ip' as source_type, ip as source, '' as ja4h, 'ip_shunning' as type, 'threat_intel' as category, status, reason, mitigated_at, unmitigated_at, updated_at, expires_at
		FROM ip_mitigations
		WHERE ` + inForceIPMitigation + `
		UNION ALL
		SELECT 'user' as source_type, fingerprint as source, ja4h, fp_type as type, category, status, reason, mitigated_at, unmitigated_at, updated_at, NULL
		FROM user_mitigations
		WHERE ` + inForceUserMitigation + `
		ORDER BY mitigated_at DESC
		LIMIT ? OFFSET ?
	`
	query = s.dialect.Rebind(query)

	ex, cleanup := s.getExecutor(ctx)
	defer cleanup()

	rows, err := ex.QueryContext(ctx, query, now, cutoff, limit, offset)
	if err != nil {
		logger.Default().LogError("failed to get combined mitigations", "error", err)
		return nil, 0
	}
	defer rows.Close()

	var res []CombinedMitigation
	for rows.Next() {
		var m CombinedMitigation
		var mitigatedAt, updatedAt time.Time
		var unmitigatedAt, expiresAt sql.NullTime
		var category sql.NullString
		if err := rows.Scan(&m.SourceType, &m.Source, &m.JA4H, &m.Type, &category, &m.Status, &m.Reason, &mitigatedAt, &unmitigatedAt, &updatedAt, &expiresAt); err == nil {
			m.MitigatedAt = mitigatedAt
			m.UpdatedAt = updatedAt
			m.Category = category.String
			if unmitigatedAt.Valid {
				m.UnmitigatedAt = &unmitigatedAt.Time
			}
			if expiresAt.Valid {
				m.ExpiresAt = &expiresAt.Time
			}
			res = append(res, m)
		}
	}
	return res, total
}

// MarkUserMitigated blocks a client class on a network: key is
// repid.For(fingerprint, address). A key without a network scope is refused
// and logged rather than written: it would name a browser build on every
// network, and IsUserMitigated never enforces one (ADR 0026).
func MarkUserMitigated(ja4plus string, fpType string, reason string, category string) {
	s := getStore()
	if s == nil || ja4plus == "" {
		return
	}
	if !repid.Scoped(ja4plus) {
		logger.Default().LogError("refused a fingerprint mitigation with no network scope; "+
			"a fingerprint on its own names a client class on every network", "fingerprint", ja4plus)
		return
	}
	// We only use the fingerprint column for JA4+ suite. ja4h column is kept for schema compatibility but left empty.
	query := s.dialect.Rebind("INSERT INTO user_mitigations (fingerprint, ja4h, fp_type, status, reason, category, mitigated_at, updated_at) VALUES (?, '', ?, 'mitigated', ?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(fingerprint, ja4h) DO UPDATE SET status = 'mitigated', reason = ?, category = ?, mitigated_at = ?, updated_at = CURRENT_TIMESTAMP")

	now := time.Now()
	_, err := s.db.Exec(query, ja4plus, fpType, reason, category, now, reason, category, now)
	if err != nil {
		logger.Default().LogError("failed to mark user as mitigated", "ja4plus", ja4plus, "error", err)
	} else {
		s.blocks.NoteKey(ja4plus, now.Add(mitigationTTL).UnixNano())
	}
	s.lookups.noteWrite()
	if s.userMitigationCache != nil {
		s.userMitigationCache.Add(ja4plus, blockedNow())
	}
	// A block ends a release this node is holding: IsUserMitigated consults
	// the release override first, so one left in place outlived the new block
	// and the fingerprint read as released until the entry was evicted.
	if s.unmitigatedCache != nil {
		s.unmitigatedCache.Remove(ja4plus)
	}
}

// MarkUserUnmitigated records that a fingerprint has been manually unmitigated
// and reports whether an in-force mitigation was actually released.
//
// The release itself is idempotent and still applies its 24h hold even when
// nothing was blocked, but "released a block" and "released nothing" are
// different answers to give an operator: the caller that reports the second as
// the first leaves a client blocked behind a success message.
func MarkUserUnmitigated(ja4plus string) bool {
	s := getStore()
	if s == nil || ja4plus == "" {
		return false
	}

	// Ask before clearing. Rows-affected on the DELETE below cannot answer this:
	// that statement also removes the UNMITIGATED_MARKER rows a previous release
	// inserted under the same key, so a second release would report itself a
	// success for deleting its own marker.
	released := s.countInForceUserMitigations(ja4plus) > 0

	// 1. Populate high-priority override cache (Bypass all security for 24h)
	s.lookups.noteWrite()
	if s.unmitigatedCache != nil {
		s.unmitigatedCache.Add(ja4plus, true)
	}

	// 2. Replace a cached block with a bounded "not blocked".
	if s.userMitigationCache != nil {
		s.userMitigationCache.Add(ja4plus, notBlocked())
	}

	// 3. Clear from DB and insert an explicit 'unmitigated' marker.
	queryDelete := s.dialect.Rebind("DELETE FROM user_mitigations WHERE fingerprint = ? OR ja4h = ?")
	_, _ = s.db.Exec(queryDelete, ja4plus, ja4plus)

	queryInsert := s.dialect.Rebind("INSERT INTO user_mitigations (fingerprint, ja4h, fp_type, status, reason, category, mitigated_at, unmitigated_at, updated_at) VALUES (?, 'UNMITIGATED_MARKER', 'JA4+', 'unmitigated', 'Manual reset', 'manual', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)")
	_, err := s.db.Exec(queryInsert, ja4plus)
	if err != nil {
		logger.Default().LogError("failed to mark user as unmitigated", "ja4plus", ja4plus, "error", err)
	}
	// Whether or not the marker was written, the block is gone from the
	// table: the list must not keep it either.
	s.blocks.NoteKey(ja4plus, blocklist.Released)
	return released
}

// ReleaseUserMitigationClass releases a fingerprint's class on every network it
// is blocked on, holds the class against being blocked again automatically for
// the hold window, and reports whether a block in force was released.
//
// A release names what an operator or a client sees: a threat's whole JA4+, or
// a legacy client's JA4 and JA4H. Blocks are kept per class and network
// (repid.For, ADR 0026), so they are found by the class alone, the way
// ResetReputationClass finds scores.
func ReleaseUserMitigationClass(fingerprint string) bool {
	s := getStore()
	if s == nil || fingerprint == "" {
		return false
	}
	class := repid.Class(fingerprint)
	released := false
	for _, key := range s.inForceUserMitigationKeysOfClass(class) {
		if MarkUserUnmitigated(key) {
			released = true
		}
	}
	// The hold, under the class itself. No block is ever written there, and
	// escalateFingerprint consults it beside the key's own (userMitigationHeld),
	// so the class stays released on every network, as a released fingerprint
	// did before blocks were scoped.
	MarkUserUnmitigated(class)
	return released
}

// maxReleasedScopes bounds one class release. The table is pruned to a day of
// blocks, and one class on this many networks at once is already a campaign
// that needs no bulk release.
const maxReleasedScopes = 10_000

// inForceUserMitigationKeysOfClass is every key a block on class is in force
// under: the class on each network it was blocked on.
func (s *pathStatsStore) inForceUserMitigationKeysOfClass(class string) []string {
	prefix := repid.ScopesOf(class)
	rows, err := s.db.Query(s.dialect.Rebind(QueryInForceUserMitigationKeysOfClass),
		mitigationCutoff(), len(prefix), prefix, maxReleasedScopes)
	if err != nil {
		logger.Default().LogError("failed to find a class's fingerprint mitigations", "class", class, "error", err)
		return nil
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var key string
		if rows.Scan(&key) == nil {
			keys = append(keys, key)
		}
	}
	return keys
}

// pruneUserMitigations removes mitigation rows past both a block's TTL and a
// release's hold. Blocks are kept per class and network, so the table would
// otherwise grow by a row for every network a class was ever blocked on.
func (s *pathStatsStore) pruneUserMitigations(ctx context.Context) {
	cutoff := time.Now().UTC().Add(-userMitigationRetention()).Format("2006-01-02 15:04:05")
	if _, err := s.db.ExecContext(ctx, s.dialect.Rebind(QueryPruneUserMitigations), cutoff); err != nil {
		logger.Default().LogError("user mitigations: prune failed", "error", err)
	}
}

// countInForceUserMitigations reports how many mitigation rows are stored under
// this exact key and are still inside the TTL IsUserMitigated enforces. An
// expired row blocks nobody, so releasing one has released nothing.
func (s *pathStatsStore) countInForceUserMitigations(ja4plus string) int {
	query := s.dialect.Rebind(`SELECT COUNT(*) FROM user_mitigations
		WHERE (fingerprint = ? OR ja4h = ?) AND status = ? AND updated_at > ?`)
	var n int
	if err := s.db.QueryRow(query, ja4plus, ja4plus, statusMitigated, mitigationCutoff()).Scan(&n); err != nil {
		logger.Default().LogError("failed to count user mitigations", "ja4plus", ja4plus, "error", err)
		return 0
	}
	return n
}

// GetTrace returns a single trace record by timestamp and ID.
// Optimized O(1) lookup using the exact Pebble key.
func GetTrace(ts time.Time, id string) *TraceRecord {
	s := getStore()
	if s == nil || s.pebble == nil {
		return nil
	}
	key := makeTraceKey(ts, id)
	val, closer, err := s.pebble.Get(key)
	if err != nil {
		return nil
	}
	defer closer.Close()

	tr := GetTraceRecord()
	if err := json.Unmarshal(val, tr); err != nil {
		tr.Reset()
		tracePool.Put(tr)
		return nil
	}
	return tr
}

func GetTraces(ctx context.Context, limit int) []*TraceRecord {
	return GetTracesFiltered(ctx, limit, false)
}

// maxTraceIDBytes bounds the ID a trace is stored under.
const maxTraceIDBytes = 128

// storableTraceID bounds and cleans a trace's ID before it is stored. The ID is
// the request's X-Request-ID as sent -- the client's to choose, up to the
// header limit -- and it becomes part of the store key and, through it, of
// every cursor and archive line. A megabyte of it, or bytes that are not
// UTF-8, which JSON would record differently from the key, serves nobody.
// It runs on the store's goroutine, not the request's.
func storableTraceID(id string) string {
	if len(id) > maxTraceIDBytes {
		id = id[:maxTraceIDBytes]
	}
	if !utf8.ValidString(id) {
		id = strings.ToValidUTF8(id, "\uFFFD")
	}
	return id
}

// ErrTraceStoreClosed is returned by trace reads when the store is not open.
var ErrTraceStoreClosed = errors.New("telemetry: the trace store is not open")

// TraceScan selects stored traces by the time their requests started.
type TraceScan struct {
	// From and To bound the scan to [From, To). A zero bound is open.
	From, To time.Time
	// Desc scans newest first.
	Desc bool
	// After resumes a scan strictly past this key, in the scan's direction.
	After []byte
}

// ScanTraces calls visit with the key and stored JSON of each trace in the
// scan, until visit returns false or ctx ends. Both slices belong to the store
// and are valid only for the duration of the call.
func ScanTraces(ctx context.Context, sc TraceScan, visit func(key, value []byte) bool) error {
	s := getStore()
	if s == nil || s.pebble == nil {
		return ErrTraceStoreClosed
	}
	return scanTraces(ctx, s.pebble.NewIter, sc, visit)
}

// iterOpener opens an iterator on the live store or on a snapshot of it.
type iterOpener func(*pebble.IterOptions) (*pebble.Iterator, error)

func scanTraces(ctx context.Context, open iterOpener, sc TraceScan, visit func(key, value []byte) bool) error {
	opts := sc.iterOptions()
	if opts.LowerBound != nil && opts.UpperBound != nil && bytes.Compare(opts.LowerBound, opts.UpperBound) >= 0 {
		return nil
	}
	iter, err := open(opts)
	if err != nil {
		return err
	}
	defer iter.Close()
	first, step := iter.First, iter.Next
	if sc.Desc {
		first, step = iter.Last, iter.Prev
	}
	n := 0
	for ok := first(); ok; ok = step() {
		if n++; n%256 == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		if !visit(iter.Key(), iter.Value()) {
			break
		}
	}
	return iter.Error()
}

// iterOptions turns the scan into Pebble bounds. The time bounds are 8-byte
// key prefixes: every key of a trace that started at or after From sorts at or
// above From's prefix, and every key of one that started before To sorts below
// To's.
func (sc TraceScan) iterOptions() *pebble.IterOptions {
	opts := &pebble.IterOptions{}
	if !sc.From.IsZero() {
		opts.LowerBound = timeKeyPrefix(sc.From)
	}
	if !sc.To.IsZero() {
		opts.UpperBound = timeKeyPrefix(sc.To)
	}
	if len(sc.After) == 0 {
		return opts
	}
	if sc.Desc {
		if opts.UpperBound == nil || bytes.Compare(sc.After, opts.UpperBound) < 0 {
			opts.UpperBound = sc.After
		}
		return opts
	}
	// The smallest key that sorts after After is After with a zero byte on it.
	next := append(bytes.Clone(sc.After), 0)
	if opts.LowerBound == nil || bytes.Compare(next, opts.LowerBound) > 0 {
		opts.LowerBound = next
	}
	return opts
}

// timeKeyPrefix is the key prefix of a trace that started at t, clamped to the
// epoch: UnixNano of an earlier time is negative and would wrap to the top of
// the keyspace.
func timeKeyPrefix(t time.Time) []byte {
	return binary.BigEndian.AppendUint64(nil, uint64(max(t.UnixNano(), 0)))
}

// OldestTraceTime returns when the oldest stored trace's request started.
func OldestTraceTime(ctx context.Context) (time.Time, bool) {
	s := getStore()
	if s == nil || s.pebble == nil {
		return time.Time{}, false
	}
	oldest, found, _ := firstTraceTime(ctx, s.pebble.NewIter)
	return oldest, found
}

func firstTraceTime(ctx context.Context, open iterOpener) (time.Time, bool, error) {
	var oldest time.Time
	found := false
	err := scanTraces(ctx, open, TraceScan{}, func(key, _ []byte) bool {
		oldest, found = TraceKeyTime(key), true
		return false
	})
	return oldest, found, err
}

// hotFloor is the later of where pruning stopped and the oldest stored trace;
// with nothing stored, it is now.
func hotFloor(prunedThrough int64, oldest time.Time, found bool) time.Time {
	if !found {
		return time.Now().UTC()
	}
	if floor := time.Unix(0, prunedThrough).UTC(); !oldest.After(floor) {
		return floor
	}
	return oldest
}

// TraceView is the trace store as it stood at one moment. A read that spans
// the store and the trace archive takes one: a prune that lands halfway
// through the read cannot then delete an hour after the read has decided the
// store is where that hour is.
type TraceView struct {
	snap  *pebble.Snapshot
	floor time.Time
}

// OpenTraceView captures the store as it is now. Close releases it.
func OpenTraceView(ctx context.Context) (*TraceView, error) {
	s := getStore()
	if s == nil || s.pebble == nil {
		return nil, ErrTraceStoreClosed
	}
	v := &TraceView{snap: s.pebble.NewSnapshot()}
	// Read after the snapshot, not before. A prune in between then puts the
	// floor above traces the snapshot still holds, which only sends a reader
	// to the archive for them, where the prune guard has made sure they are.
	// In the other order it would send the reader to the snapshot for traces
	// already gone from it.
	pruned := s.tracesPrunedThrough.Load()
	oldest, found, err := firstTraceTime(ctx, v.snap.NewIter)
	if err != nil {
		v.Close()
		return nil, err
	}
	v.floor = hotFloor(pruned, oldest, found)
	return v, nil
}

// Floor is TraceHotFloor as of the view's moment.
func (v *TraceView) Floor() time.Time { return v.floor }

// Scan is ScanTraces over the view.
func (v *TraceView) Scan(ctx context.Context, sc TraceScan, visit func(key, value []byte) bool) error {
	return scanTraces(ctx, v.snap.NewIter, sc, visit)
}

// Close releases the view.
func (v *TraceView) Close() { _ = v.snap.Close() }

// TraceIter walks a view's traces in a scan's order, one at a time. A reader
// merging the store with other sources in key order pulls from it rather than
// being pushed to, as ScanTraces does.
type TraceIter struct {
	it      *pebble.Iterator
	desc    bool
	started bool
}

// Iter opens an iterator over the view for the scan. Close it.
func (v *TraceView) Iter(sc TraceScan) (*TraceIter, error) {
	opts := sc.iterOptions()
	if opts.LowerBound != nil && opts.UpperBound != nil && bytes.Compare(opts.LowerBound, opts.UpperBound) >= 0 {
		return &TraceIter{}, nil // an empty range
	}
	it, err := v.snap.NewIter(opts)
	if err != nil {
		return nil, err
	}
	return &TraceIter{it: it, desc: sc.Desc}, nil
}

// Next moves to the next trace in the scan's order and reports whether there
// is one.
func (t *TraceIter) Next() bool {
	switch {
	case t.it == nil:
		return false
	case !t.started && t.desc:
		t.started = true
		return t.it.Last()
	case !t.started:
		t.started = true
		return t.it.First()
	case t.desc:
		return t.it.Prev()
	default:
		return t.it.Next()
	}
}

// Key is the current trace's store key, valid until the next call to Next.
func (t *TraceIter) Key() []byte { return t.it.Key() }

// Value is the current trace's stored JSON, valid until the next call to Next.
func (t *TraceIter) Value() []byte { return t.it.Value() }

// Err is the error, if any, that ended the iteration.
func (t *TraceIter) Err() error {
	if t.it == nil {
		return nil
	}
	return t.it.Error()
}

// Close releases the iterator.
func (t *TraceIter) Close() error {
	if t.it == nil {
		return nil
	}
	return t.it.Close()
}

// TraceHotFloor returns the time from which the store holds every trace it
// has recorded: before it, traces have been pruned (or were never here); from
// it on, none has been deleted. A reader wanting a period older than the floor
// has to look somewhere else -- the trace archive -- and one wanting a newer
// period will find it all here.
//
// It is the later of where pruning stopped and the oldest stored trace, not
// either alone. A trace whose request outlived the retention window is written
// with a key below the last prune, which would make the oldest trace a floor
// the store cannot honour; and a store that has been emptied or replaced holds
// nothing from before its oldest trace, whatever it pruned.
func TraceHotFloor(ctx context.Context) time.Time {
	s := getStore()
	if s == nil || s.pebble == nil {
		return time.Now().UTC()
	}
	oldest, found, _ := firstTraceTime(ctx, s.pebble.NewIter)
	return hotFloor(s.tracesPrunedThrough.Load(), oldest, found)
}

// TraceStoreActive reports whether new traces are being recorded.
func TraceStoreActive() bool {
	s := getStore()
	return s != nil && s.traceStoreEnabled.Load()
}

// GetTracesFiltered returns the last N traces with an optional summary mode.
// In summary mode, large fields (bodies, headers) are omitted from unmarshaling.
func GetTracesFiltered(ctx context.Context, limit int, summary bool) []*TraceRecord {
	s := getStore()
	if s == nil || s.pebble == nil {
		return nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	iter, _ := s.pebble.NewIter(&pebble.IterOptions{})
	defer iter.Close()
	res := make([]*TraceRecord, 0, min(limit, 100))
	seen := make(map[string]struct{})

	// Start from the end (most recent)
	for ok := iter.Last(); ok && len(res) < limit; ok = iter.Prev() {
		tr := GetTraceRecord()
		if summary {
			// Use a specialized summary unmarshaler to avoid CPU overhead on large bodies
			if err := UnmarshalTraceSummary(iter.Value(), tr); err == nil {
				if _, ok := seen[tr.ID]; ok {
					tr.Reset()
					tracePool.Put(tr)
					continue
				}
				seen[tr.ID] = struct{}{}
				res = append(res, tr)
			} else {
				tr.Reset()
				tracePool.Put(tr)
			}
		} else {
			if err := json.Unmarshal(iter.Value(), tr); err == nil {
				if _, ok := seen[tr.ID]; ok {
					tr.Reset()
					tracePool.Put(tr)
					continue
				}
				seen[tr.ID] = struct{}{}
				res = append(res, tr)
			} else {
				tr.Reset()
				tracePool.Put(tr)
			}
		}
	}
	return res
}

// UnmarshalTraceSummary unmarshals basic fields but omits heavy payloads.
func UnmarshalTraceSummary(data []byte, tr *TraceRecord) error {
	// We use a temporary struct with only the fields we need to avoid unmarshaling
	// large body/header strings into the final TraceRecord.
	type summary struct {
		ID              string    `json:"id"`
		OperationName   string    `json:"operationName"`
		ServiceName     string    `json:"serviceName"`
		DurationMs      float64   `json:"durationMs"`
		Timestamp       time.Time `json:"timestamp"`
		Status          string    `json:"status"`
		Path            string    `json:"path"`
		Host            string    `json:"host"`
		SourceIP        string    `json:"sourceIp"`
		Method          string    `json:"method"`
		UserAgent       string    `json:"userAgent"`
		Referer         string    `json:"referer"`
		JA4             string    `json:"ja4"`
		JA4H            string    `json:"ja4h"`
		Fingerprint     string    `json:"fingerprint"`
		CountryCode     string    `json:"countryCode"`
		RouteID         string    `json:"routeId"`
		Reputation      float64   `json:"reputation"`
		EntrypointDelay float64   `json:"entrypointDelayMs"`
		RouteDelay      float64   `json:"routeDelayMs"`
		MiddlewareDelay float64   `json:"middlewareDelayMs"`
		ServiceDelay    float64   `json:"serviceDelayMs"`
		PasswordAuth    bool      `json:"passwordAuth"`
		Refusal         string    `json:"refusal"`
	}
	var s summary
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	tr.PasswordAuth = s.PasswordAuth
	tr.Refusal = s.Refusal
	tr.ID = s.ID
	tr.OperationName = s.OperationName
	tr.ServiceName = s.ServiceName
	tr.DurationMs = s.DurationMs
	tr.Timestamp = s.Timestamp
	tr.Status = s.Status
	tr.Path = s.Path
	tr.Host = s.Host
	tr.SourceIP = s.SourceIP
	tr.Method = s.Method
	tr.UserAgent = s.UserAgent
	tr.Referer = s.Referer
	tr.JA4 = s.JA4
	tr.JA4H = s.JA4H
	tr.Fingerprint = s.Fingerprint
	tr.CountryCode = s.CountryCode
	tr.RouteID = s.RouteID
	tr.Reputation = s.Reputation
	tr.EntrypointDelay = s.EntrypointDelay
	tr.RouteDelay = s.RouteDelay
	tr.MiddlewareDelay = s.MiddlewareDelay
	tr.ServiceDelay = s.ServiceDelay
	return nil
}

// GetPathStatsWindow returns aggregated stats from storage for the last `days` days.
// Falls back to in-memory stats on DB errors to ensure metrics are always available.
func GetPathStatsWindow(ctx context.Context, days int) []PathStats {
	s := getStore()
	if s == nil {
		return getInMemoryPathStats()
	}
	if days <= 0 {
		days = int(s.retentionDays.Load())
	}
	cutoff := time.Now().AddDate(0, 0, -days+1).UTC().Format("2006-01-02")
	q := s.dialect.Rebind(QueryGetPathStatsWin)

	ex, cleanup := s.getExecutor(ctx)
	defer cleanup()

	rows, err := ex.QueryContext(ctx, q, cutoff)
	if err != nil {
		logQueryErr(ctx, "path stats: DB query failed, falling back to in-memory stats", err)
		return getInMemoryPathStats()
	}
	defer rows.Close()
	res := make([]PathStats, 0, 256)
	for rows.Next() {
		var host, p string
		var rc int64
		var lsum float64
		var bsum int64
		if err := rows.Scan(&host, &p, &rc, &lsum, &bsum); err != nil {
			logger.Default().LogError("path stats: scan row failed", "error", err)
			continue
		}
		avg := 0.0
		if rc > 0 {
			avg = lsum / float64(rc)
		}
		res = append(res, PathStats{
			Host:              host,
			Path:              p,
			RequestCount:      uint64(rc),
			BytesTotal:        uint64(max(bsum, 0)),
			LatencySumSeconds: SafeFloat(lsum),
			AvgLatencySeconds: SafeFloat(float64(int(avg*1000+0.5)) / 1000.0),
		})
	}
	return res
}

// GetDomainStatsRolling24h returns aggregated domain statistics for the last 24 hours.
func GetDomainStatsRolling24h(ctx context.Context) []DomainStats {
	return GetDomainStatsWindow(ctx, 1)
}

// GetDomainStatsWindow returns aggregated domain statistics for the last N days.
func GetDomainStatsWindow(ctx context.Context, days int) []DomainStats {
	s := getStore()
	if s == nil {
		return nil
	}

	var q string
	var args []any

	if days == 1 {
		now := time.Now().UTC()
		today := now.Format("2006-01-02")
		yesterday := now.AddDate(0, 0, -1).Format("2006-01-02")
		bucket := now.Hour()*2 + now.Minute()/30
		q = s.dialect.Rebind(QueryGetDomainStatsRolling24h)
		args = []any{today, bucket, yesterday, bucket}
	} else {
		if days <= 0 {
			days = int(s.retentionDays.Load())
		}
		cutoff := time.Now().AddDate(0, 0, -days+1).UTC().Format("2006-01-02")
		q = s.dialect.Rebind(QueryGetDomainStatsWin)
		args = []any{cutoff}
	}

	ex, cleanup := s.getExecutor(ctx)
	defer cleanup()

	rows, err := ex.QueryContext(ctx, q, args...)
	if err != nil {
		logQueryErr(ctx, "domain stats: query failed", err)
		return nil
	}
	defer rows.Close()

	var stats []DomainStats
	for rows.Next() {
		var domain string
		var rc int64
		var lsum float64
		var bsum int64
		if err := rows.Scan(&domain, &rc, &lsum, &bsum); err != nil {
			continue
		}
		avg := 0.0
		if rc > 0 {
			avg = lsum / float64(rc)
		}
		stats = append(stats, DomainStats{
			Domain:            domain,
			RequestCount:      uint64(rc),
			BytesTotal:        uint64(max(bsum, 0)),
			LatencySumSeconds: SafeFloat(lsum),
			AvgLatencySeconds: SafeFloat(float64(int(avg*1000+0.5)) / 1000.0),
		})
	}
	return stats
}

// GetSystemTrafficRolling24h returns total requests and bandwidth for today (since UTC midnight).
func GetSystemTrafficRolling24h(ctx context.Context) (uint64, uint64) {
	s := getStore()
	if s == nil {
		return 0, 0
	}
	return s.currentReqToday.Load(), s.currentBytesToday.Load()
}

// logQueryErr logs a query failure unless it was caused by the caller's
// context being canceled or timing out — which happens routinely when a
// dashboard client disconnects or aborts an in-flight poll. Those are
// expected and would otherwise flood the log at ERROR level, masking real
// faults.
func logQueryErr(ctx context.Context, msg string, err error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
		return
	}
	logger.Default().LogError(msg, "error", err)
}

// GetSystemTrafficHistory returns traffic samples for the last N days.
func GetSystemTrafficHistory(ctx context.Context, days int) []TrafficSample {
	s := getStore()
	if s == nil {
		return nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02")
	// For long spans collapse each day into a single bucket so the result set
	// stays small (bounded memory and snapshot size).
	query := QueryGetTrafficHistory
	if days > trafficDailyAggregationThresholdDays {
		query = QueryGetTrafficHistoryDaily
	}
	q := s.dialect.Rebind(query)
	ex, cleanup := s.getExecutor(ctx)
	defer cleanup()

	rows, err := ex.QueryContext(ctx, q, cutoff)
	if err != nil {
		logQueryErr(ctx, "traffic history: query failed", err)
		return nil
	}
	defer rows.Close()

	var samples []TrafficSample
	for rows.Next() {
		var day string
		var bucket int
		var rc, bsum int64
		if err := rows.Scan(&day, &bucket, &rc, &bsum); err != nil {
			continue
		}

		t, err := time.Parse("2006-01-02", day)
		if err != nil {
			// Try robust parsing
			if len(day) > 10 {
				day = day[:10]
			}
			t, err = time.Parse("2006-01-02", day)
		}

		if err == nil {
			// bucket is half-hour index (0-47)
			t = t.Add(time.Duration(bucket*30) * time.Minute)
			samples = append(samples, TrafficSample{
				Timestamp: t.UnixMilli(),
				Requests:  uint64(rc),
				Bytes:     uint64(bsum),
			})
		} else {
			logger.Default().LogError("traffic history: failed to parse day", "day", day, "error", err)
		}
	}
	if err := rows.Err(); err != nil {
		logQueryErr(ctx, "traffic history: rows error", err)
	}
	return samples
}

// GetDomainStatsHourly returns domain statistics for a specific hour.
func GetDomainStatsHourly(day string, hour int) []DomainStats {
	s := getStore()
	if s == nil {
		return nil
	}
	q := s.dialect.Rebind(QueryGetDomainStatsHourly)
	ex, cleanup := s.getExecutor(context.Background())
	defer cleanup()
	rows, err := ex.QueryContext(context.Background(), q, day, hour)
	if err != nil {
		logger.Default().LogError("domain stats: hourly query failed", "error", err)
		return nil
	}
	defer rows.Close()

	var stats []DomainStats
	for rows.Next() {
		var domain string
		var hr int
		var rc int64
		var lsum float64
		var bsum int64
		if err := rows.Scan(&domain, &hr, &rc, &lsum, &bsum); err != nil {
			continue
		}
		avg := 0.0
		if rc > 0 {
			avg = lsum / float64(rc)
		}
		stats = append(stats, DomainStats{
			Domain:            domain,
			Hour:              hr,
			RequestCount:      uint64(rc),
			BytesTotal:        uint64(max(bsum, 0)),
			LatencySumSeconds: lsum,
			AvgLatencySeconds: float64(int(avg*1000+0.5)) / 1000.0,
		})
	}
	return stats
}

// GetActiveThreatsRolling24h returns the count of active threats for the last 24 hours.
func GetActiveThreatsRolling24h(ctx context.Context) int {
	s := getStore()
	if s == nil {
		return 0
	}
	// Prefer the in-memory atomic counter if available (current day)
	return int(s.currentActiveToday.Load())
}

// GetMitigatedRolling24h returns the count of threats actively mitigated
// (blocked/challenged/shunned) for the last 24 hours.
func GetMitigatedRolling24h(ctx context.Context) int {
	s := getStore()
	if s == nil {
		return 0
	}
	// Prefer the in-memory atomic counter if available (current day)
	return int(s.currentMitigatedToday.Load())
}

// GetSecurityThreatByID returns a single security threat by its unique ID.
func GetSecurityThreatByID(ctx context.Context, id string) (*SecurityThreat, error) {
	s := getStore()
	if s == nil {
		return nil, errors.New("telemetry store not initialized")
	}
	if id == "" {
		return nil, errors.New("threat ID is required")
	}

	query := s.dialect.Rebind("SELECT id, type, source_ip, fingerprint, score, details, timestamp, ja4, ja4h, route_id, request_uri, category, severity, asn, action_taken, country_code, COALESCE(request_headers, ''), COALESCE(request_body, ''), COALESCE(response_headers, ''), COALESCE(response_body, ''), COALESCE(t.user_agent, ''), COALESCE(t.method, ''), confidence, entropy, cluster_size, COALESCE(recommendation, ''), COALESCE(triggered_rules, ''), reputation, source_ips FROM security_threats t WHERE id = ?")
	ex, cleanup := s.getExecutor(ctx)
	defer cleanup()

	th := &SecurityThreat{}
	var sourceIPs string
	err := ex.QueryRowContext(ctx, query, id).Scan(&th.ID, &th.Type, &th.SourceIP, &th.Fingerprint, &th.Score, &th.Details, &th.Time, &th.JA4, &th.JA4H, &th.RouteID, &th.RequestURI, &th.Category, &th.Severity, &th.ASN, &th.ActionTaken, &th.CountryCode, &th.RequestHeaders, &th.RequestBody, &th.ResponseHeaders, &th.ResponseBody, &th.UserAgent, &th.Method, &th.Confidence, &th.Entropy, &th.ClusterSize, &th.Recommendation, &th.TriggeredRules, &th.Reputation, &sourceIPs)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("threat with ID %s not found", id)
		}
		return nil, err
	}
	if sourceIPs != "" {
		th.SourceIPs = strings.Split(sourceIPs, ",")
	}
	th.Mitigated = isMitigatingAction(th.ActionTaken)
	return th, nil
}

func buildThreatFilterQuery(dialect db.Dialect, filter *ThreatFilter, usePrefix bool) (string, []any) {
	if filter == nil {
		return "", nil
	}
	var conditions []string
	var args []any
	prefix := ""
	if usePrefix {
		prefix = "t."
	}

	if filter.Search != "" {
		s := "%" + filter.Search + "%"
		conditions = append(conditions, fmt.Sprintf("(%ssource_ip LIKE ? OR %sfingerprint LIKE ? OR %sja4 LIKE ? OR %sdetails LIKE ? OR %stype LIKE ? OR %scategory LIKE ?)", prefix, prefix, prefix, prefix, prefix, prefix))
		args = append(args, s, s, s, s, s, s)
	}
	if filter.Category != "" && filter.Category != "all" {
		conditions = append(conditions, prefix+"category = ?")
		args = append(args, filter.Category)
	}
	switch filter.Status {
	case statusMitigated:
		// Mitigated if:
		// 1. Current status is 'mitigated' in IP or fingerprint table
		// 2. OR it was blocked at the time AND not subsequently unmitigated in any table
		conditions = append(conditions, fmt.Sprintf("(m.status = 'mitigated' OR fm4.status = 'mitigated' OR (%saction_taken IN ('blocked', 'challenged', 'shunned') AND (m.status IS NULL OR m.status != 'unmitigated') AND (fm4.status IS NULL OR fm4.status != 'unmitigated')))", prefix))
	case "detected":
		// Detected (active threat) if:
		// 1. Current status is 'unmitigated' in any table
		// 2. OR it was NOT blocked at the time AND not currently mitigated in any table
		conditions = append(conditions, fmt.Sprintf("((m.status IS NULL OR m.status != 'mitigated') AND (fm4.status IS NULL OR fm4.status != 'mitigated') AND (%saction_taken NOT IN ('blocked', 'challenged', 'shunned') OR m.status = 'unmitigated' OR fm4.status = 'unmitigated'))", prefix))
	}

	if len(conditions) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conditions, " AND "), args
}

// GetAssociatedFingerprints returns a list of unique fingerprints (including JA4) associated with an IP.
func GetAssociatedFingerprints(ctx context.Context, ip string) []string {
	s := getStore()
	if s == nil || ip == "" {
		return nil
	}
	// Query for unique JA4+ fingerprints (ja4_ja4h) seen from this IP.
	// We use UNION to capture both explicitly set 'fingerprint' column and reconstructed ja4+ja4h.
	query := s.dialect.Rebind("SELECT DISTINCT fingerprint FROM security_threats WHERE source_ip = ? AND fingerprint != '' " +
		"UNION SELECT DISTINCT ja4 || '_' || ja4h FROM security_threats WHERE source_ip = ? AND ja4 != '' AND ja4h != ''")
	ex, cleanup := s.getExecutor(ctx)
	defer cleanup()

	rows, err := ex.QueryContext(ctx, query, ip, ip)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var fps []string
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err == nil && fp != "" {
			fps = append(fps, fp)
		}
	}
	return fps
}

// FlushThreats blocks until all enqueued security threats are processed and persisted to DB.
func FlushThreats() { flushQueues() }

// FlushTraces blocks until every trace recorded before it is in the trace
// store. It is the same barrier as FlushThreats -- one flush drains every
// intake -- under the name a caller waiting for traces looks for; without it,
// tests slept and hoped the timed flush had run.
func FlushTraces() { flushQueues() }

func flushQueues() {
	s := getStore()
	if s == nil {
		return
	}
	ack := make(chan struct{})
	select {
	case s.flushCh <- ack:
		<-ack
	case <-time.After(5 * time.Second):
		// timeout to avoid blocking forever if loop is stuck
	}
}

// Bounds for a threat query. The lower bound matters as much as the upper one:
// the result slice is sized with min(limit, 100) as its capacity, and make()
// panics on a negative capacity rather than treating it as zero.
const (
	defaultThreatQueryLimit = 100
	maxThreatQueryLimit     = 1000
)

// clampThreatBounds normalises the paging bounds for a threat query.
//
// It exists because two threat queries had drifted: the Lite variant guarded a
// nil store, a non-positive limit and a negative offset, while the full-blob
// list variant guarded only the offset — so the one that could end a goroutine
// was the one left open. That second query has since been deleted as dead
// code, but sharing the rule is what stops the survivors diverging again.
func clampThreatBounds(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = defaultThreatQueryLimit
	}
	if limit > maxThreatQueryLimit {
		limit = maxThreatQueryLimit
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// GetSecurityThreatsLite returns a paged list of recent security threats WITHOUT
// the heavyweight request/response header and body blobs. It is used on the hot
// dashboard-snapshot path (polled every couple of seconds), where those blobs are
// never rendered: fetching them needlessly scans four LONGTEXT columns per row,
// which under load blows the snapshot's request deadline ("threats: scan failed:
// context deadline exceeded") and bloats the SSE payload. The detail view goes
// through GetSecurityThreatByID, which selects the blobs for one threat; the
// full-blob *list* variant was deleted as dead code -- nothing ever called it,
// and its SELECT had drifted to omit source_ips, so wiring it up would have
// returned every threat with an empty IP cluster.
func GetSecurityThreatsLite(ctx context.Context, limit, offset int, filter *ThreatFilter) []*SecurityThreat {
	s := getStore()
	if s == nil {
		return nil
	}
	limit, offset = clampThreatBounds(limit, offset)

	where, args := buildThreatFilterQuery(s.dialect, filter, true)
	query := s.dialect.Rebind("SELECT t.id, t.type, t.source_ip, t.fingerprint, t.score, t.details, t.timestamp, t.ja4, t.ja4h, t.route_id, t.request_uri, t.category, t.severity, t.asn, t.action_taken, t.country_code, t.latitude, t.longitude, COALESCE(t.user_agent, ''), COALESCE(t.method, ''), COALESCE(t.recommendation, ''), COALESCE(t.triggered_rules, ''), t.reputation, COALESCE(m.status, ''), COALESCE(fm4.status, ''), t.source_ips FROM security_threats t LEFT JOIN ip_mitigations m ON t.source_ip = m.ip LEFT JOIN user_mitigations fm4 ON t.ja4 = fm4.fingerprint AND (fm4.ja4h = '' OR fm4.ja4h = t.ja4h) " + where + " ORDER BY t.timestamp DESC LIMIT ? OFFSET ?")
	args = append(args, limit, offset)

	ex, cleanup := s.getExecutor(ctx)
	defer cleanup()

	rows, err := ex.QueryContext(ctx, query, args...)
	if err != nil {
		logQueryErr(ctx, "threats: query failed", err)
		return nil
	}
	defer rows.Close()
	// min(limit, 100), spelled as a comparison: CodeQL does not read the
	// builtin as a bound and reports a caller-sized allocation.
	capacity := defaultThreatQueryLimit
	if limit < capacity {
		capacity = limit
	}
	res := make([]*SecurityThreat, 0, capacity)
	for rows.Next() {
		if ctx.Err() != nil {
			break
		}
		th := &SecurityThreat{}
		var mitigationStatus, fm4Status string
		var sourceIPs string
		if err := rows.Scan(&th.ID, &th.Type, &th.SourceIP, &th.Fingerprint, &th.Score, &th.Details, &th.Time, &th.JA4, &th.JA4H, &th.RouteID, &th.RequestURI, &th.Category, &th.Severity, &th.ASN, &th.ActionTaken, &th.CountryCode, &th.Latitude, &th.Longitude, &th.UserAgent, &th.Method, &th.Recommendation, &th.TriggeredRules, &th.Reputation, &mitigationStatus, &fm4Status, &sourceIPs); err != nil {
			logQueryErr(ctx, "threats lite: scan failed", err)
			continue
		}
		if sourceIPs != "" {
			th.SourceIPs = strings.Split(sourceIPs, ",")
		}
		mitigationStatus = s.ipv6ShunStatus(th.SourceIP, mitigationStatus)
		th.Mitigated = mitigationStatus == statusMitigated || fm4Status == statusMitigated ||
			((isMitigatingAction(th.ActionTaken)) &&
				mitigationStatus != "unmitigated" && fm4Status != "unmitigated")
		res = append(res, th)
	}
	return res
}

// ipv6ShunStatus is the shun status a threat from ip is listed with. The
// join reads the row keyed by the threat's own address, and an IPv6 address
// is shunned under its /64's key (ADR 0058), which SQL cannot compute: so an
// IPv6 threat the join found nothing for is shown as shunned when the block
// list holds its /64. A release there is not shown -- the threat reads as
// one never shunned -- and the dashboard's "mitigated" filter, which runs in
// SQL, still matches IPv6 threats by their own address.
func (s *pathStatsStore) ipv6ShunStatus(ip, joined string) string {
	if joined != "" || strings.IndexByte(ip, ':') < 0 || !s.listedIPBlock(ip) {
		return joined
	}
	return statusMitigated
}

// CountSecurityThreats returns the total number of security threats in the store.
func CountSecurityThreats(ctx context.Context, filter *ThreatFilter) int64 {
	s := getStore()
	if s == nil {
		return 0
	}
	useJoin := filter != nil && filter.Status != "" && filter.Status != "all"
	where, args := buildThreatFilterQuery(s.dialect, filter, useJoin)
	var query string
	if useJoin {
		query = s.dialect.Rebind("SELECT COUNT(*) FROM security_threats t LEFT JOIN ip_mitigations m ON t.source_ip = m.ip LEFT JOIN user_mitigations fm4 ON t.ja4 = fm4.fingerprint AND (fm4.ja4h = '' OR fm4.ja4h = t.ja4h) " + where)
	} else {
		query = s.dialect.Rebind("SELECT COUNT(*) FROM security_threats " + where)
	}
	var count int64
	ex, cleanup := s.getExecutor(ctx)
	defer cleanup()

	err := ex.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0
	}
	return count
}

func IsStoreEnabled() bool {
	return getStore() != nil
}

// PingStore checks the health of the telemetry database.
func PingStore(ctx context.Context) error {
	s := getStore()
	if s == nil {
		return fmt.Errorf("telemetry store not initialized")
	}
	return s.db.PingContext(ctx)
}

// CurrentRetentionDays returns the active retention configuration.
func CurrentRetentionDays() int {
	s := getStore()
	if s == nil {
		return 0
	}
	return int(s.retentionDays.Load())
}

// maxDashboardTrendWindowDays caps the dashboard trend window to one year so
// that month/year filtering is supported while keeping the snapshot payload,
// memory and query cost bounded regardless of the configured retention.
const maxDashboardTrendWindowDays = 366

// dashboardTrendWindowDays returns the span (in days) of history the dashboard
// trend charts should cover: at least one day, at most one year, and never more
// than the configured retention.
func dashboardTrendWindowDays() int {
	days := CurrentRetentionDays()
	if days <= 0 {
		days = 2
	}
	// Always return at least 2 days so rolling 24h charts have coverage
	// even when called at the start of a calendar day.
	return min(max(days, 2), maxDashboardTrendWindowDays)
}

// GetTopThreatSources returns the most frequent attacking IP addresses.
func GetTopThreatSources(ctx context.Context, limit int) []LabeledCount {
	s := getStore()
	if s == nil {
		return nil
	}
	query := s.dialect.Rebind("SELECT source_ip, COUNT(*) as cnt, MAX(asn) FROM security_threats WHERE source_ip != '' GROUP BY source_ip ORDER BY cnt DESC LIMIT ?")
	ex, cleanup := s.getExecutor(ctx)
	defer cleanup()

	rows, err := ex.QueryContext(ctx, query, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var res []LabeledCount
	for rows.Next() {
		var label string
		var asn string
		var count float64
		if err := rows.Scan(&label, &count, &asn); err != nil {
			logger.Default().LogError("top threat sources: scan failed", "error", err)
			continue
		}
		res = append(res, LabeledCount{Label: label, Value: count, Subtext: asn})
	}
	return res
}

// GetTopThreatTypes returns the most frequent types of security threats.
func GetTopThreatTypes(ctx context.Context, limit int) []LabeledCount {
	s := getStore()
	if s == nil {
		return nil
	}
	query := s.dialect.Rebind("SELECT type, COUNT(*) as cnt FROM security_threats GROUP BY type ORDER BY cnt DESC LIMIT ?")
	ex, cleanup := s.getExecutor(ctx)
	defer cleanup()

	rows, err := ex.QueryContext(ctx, query, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var res []LabeledCount
	for rows.Next() {
		var label string
		var count float64
		if err := rows.Scan(&label, &count); err != nil {
			logger.Default().LogError("top threat types: scan failed", "error", err)
			continue
		}
		res = append(res, LabeledCount{Label: label, Value: count})
	}
	return res
}

// GetThreats by country returns the distribution of threats by country.
func GetThreatsByCountry(ctx context.Context, limit int) []LabeledCount {
	s := getStore()
	if s == nil {
		return nil
	}
	query := s.dialect.Rebind("SELECT country_code, COUNT(*) as cnt FROM security_threats WHERE country_code != '' GROUP BY country_code ORDER BY cnt DESC LIMIT ?")
	ex, cleanup := s.getExecutor(ctx)
	defer cleanup()

	rows, err := ex.QueryContext(ctx, query, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var res []LabeledCount
	for rows.Next() {
		var label string
		var count float64
		if err := rows.Scan(&label, &count); err != nil {
			logger.Default().LogError("threats by country: scan failed", "error", err)
			continue
		}
		res = append(res, LabeledCount{Label: label, Value: count})
	}
	return res
}

// attackTrendBucketQuery builds the threat-count trend query.
//
// SQLite has no timestamp type: the driver stores a time.Time as Go's own
// text ("2026-10-02 16:39:31.975189 +0700 WIB m=+25.13"), which strftime()
// and date() cannot parse, so every row fell into one NULL bucket that the
// reader then dropped and the chart was always empty (T28). The bucket is cut
// from the text instead -- its first 13 characters are the hour, its first 10
// the day, in the writer's local time -- and one row's full timestamp comes
// back with it so the reader knows which zone that local time was in.
//
// Postgres stores the same local wall clock in a timestamp without time zone,
// and date_trunc works on it.
func attackTrendBucketQuery(driver string, daily bool) string {
	isPostgres := driver == db.DriverPostgres || driver == "pgx"
	switch {
	case isPostgres && daily:
		return "SELECT date_trunc('day', timestamp) as bucket, MIN(timestamp) as sample, COUNT(*) as cnt FROM security_threats WHERE timestamp >= ? GROUP BY bucket ORDER BY bucket ASC"
	case isPostgres:
		return "SELECT date_trunc('hour', timestamp) as bucket, MIN(timestamp) as sample, COUNT(*) as cnt FROM security_threats WHERE timestamp >= ? GROUP BY bucket ORDER BY bucket ASC"
	case daily:
		return "SELECT substr(timestamp, 1, 10) as bucket, MIN(timestamp) as sample, COUNT(*) as cnt FROM security_threats WHERE timestamp >= ? GROUP BY bucket ORDER BY bucket ASC"
	default:
		return "SELECT substr(timestamp, 1, 13) as bucket, MIN(timestamp) as sample, COUNT(*) as cnt FROM security_threats WHERE timestamp >= ? GROUP BY bucket ORDER BY bucket ASC"
	}
}

// GetAttackTrend returns a time-series of security threat counts: one sample
// per hour, or per day past attackTrendDailyThresholdDays, stamped with the
// bucket's start.
func GetAttackTrend(ctx context.Context, days int) []TrafficSample {
	s := getStore()
	if s == nil {
		return nil
	}
	if days <= 0 {
		days = 1
	}
	cutoff := time.Now().Add(time.Duration(-days*24) * time.Hour).Format(threatTimestampLayout)
	daily := days > attackTrendDailyThresholdDays
	query := attackTrendBucketQuery(s.dialect.Driver, daily)

	ex, cleanup := s.getExecutor(ctx)
	defer cleanup()

	rows, err := ex.QueryContext(ctx, s.dialect.Rebind(query), cutoff)
	if err != nil {
		logger.Default().LogError("attack trend: query failed", "error", err)
		return nil
	}
	defer rows.Close()

	counts := make(map[int64]uint64, 48) // typical dashboard view
	for rows.Next() {
		var bucket, sample any
		var count uint64
		if err := rows.Scan(&bucket, &sample, &count); err != nil {
			continue
		}
		if t, ok := parseThreatTimestamp(sample); ok {
			counts[trendBucketStart(t, daily).UnixMilli()] += count
		}
	}
	res := make([]TrafficSample, 0, len(counts))
	for ts, n := range counts {
		res = append(res, TrafficSample{Timestamp: ts, Requests: n})
	}
	slices.SortFunc(res, func(a, b TrafficSample) int { return cmp.Compare(a.Timestamp, b.Timestamp) })
	return res
}

// trendBucketStart is the start of t's hour (or day) in t's own zone.
func trendBucketStart(t time.Time, daily bool) time.Time {
	hour := t.Hour()
	if daily {
		hour = 0
	}
	return time.Date(t.Year(), t.Month(), t.Day(), hour, 0, 0, 0, t.Location())
}

// threatTimestampLayouts are the forms security_threats.timestamp is found
// in: the SQLite driver's (Go's time.String without the monotonic part),
// SQLite's own, and the layout this package compares against.
var threatTimestampLayouts = []string{
	"2006-01-02 15:04:05.999999999 -0700 MST",
	"2006-01-02 15:04:05.999999999-07:00",
	time.RFC3339Nano,
}

// parseThreatTimestamp reads one stored threat timestamp. A time.Time is what
// lib/pq returns for a timestamp without time zone: the writer's local wall
// clock labelled UTC, which is re-read as local time. Text with no zone is
// local for the same reason.
func parseThreatTimestamp(v any) (time.Time, bool) {
	switch x := v.(type) {
	case time.Time:
		return time.Date(x.Year(), x.Month(), x.Day(), x.Hour(), x.Minute(), x.Second(), x.Nanosecond(), time.Local), true
	case []byte:
		return parseThreatTimestamp(string(x))
	case string:
		text, _, _ := strings.Cut(x, " m=")
		for _, layout := range threatTimestampLayouts {
			if t, err := time.Parse(layout, text); err == nil {
				return t, true
			}
		}
		if t, err := time.ParseInLocation(threatTimestampLayout, text, time.Local); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
