// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/audit"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/syncutil"
	lru "github.com/hashicorp/golang-lru"
)

// RedactHeaders masks sensitive headers like Authorization and X-Api-Key.
// It is optimized to minimize allocations by using a pooled strings.Builder and avoiding strings.Split.
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
		var line string
		if end == -1 {
			line = headers[start:]
		} else {
			line = headers[start : start+end]
		}

		// Fast path: check for common sensitive header prefixes case-insensitively without allocations
		isSensitive := false
		if len(line) >= 7 { // shortest is "cookie:"
			if (len(line) >= 14 && strings.EqualFold(line[:14], "authorization:")) ||
				(len(line) >= 10 && strings.EqualFold(line[:10], "x-api-key:")) ||
				(len(line) >= 7 && strings.EqualFold(line[:7], "cookie:")) ||
				(len(line) >= 11 && strings.EqualFold(line[:11], "set-cookie:")) ||
				(len(line) >= 13 && strings.EqualFold(line[:13], "x-auth-token:")) {
				isSensitive = true
			}
		}

		if isSensitive {
			if colon := strings.IndexByte(line, ':'); colon != -1 {
				sb.WriteString(line[:colon])
				sb.WriteString(": [REDACTED]")
			} else {
				sb.WriteString(line)
			}
		} else {
			sb.WriteString(line)
		}

		if end == -1 {
			break
		}
		sb.WriteByte('\n')
		start += end + 1
	}
	return sb.String()
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

	// ipMaliciousFingerprints tracks unique malicious fingerprints per IP for escalation to IP shunning.
	// map[IP]map[Fingerprint]struct{}
	ipMaliciousFingerprints, _ = lru.NewARC(10000)
	ipMaliciousMu              sync.Mutex

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
// Supports SQLite, PostgreSQL, MySQL, and MariaDB.

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
	// Internal fields for lazy formatting in background worker
	rawReqHeader  map[string][]string
	rawRespHeader map[string][]string
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
}

type ThreatFilter struct {
	Search   string
	Category string
	Status   string // all, mitigated, detected
}

type pathStatsStore struct {
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
	traceStoreEnabled           atomic.Bool

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
func InitPathStatsStore(databaseURL string, retentionDays int) error {
	storeMu.Lock()
	defer storeMu.Unlock()
	if store != nil {
		return nil
	}
	return initStore(databaseURL, retentionDays)
}

// resolveTraceDir picks the directory for the Pebble trace store.
//
// GATEON_TRACE_DIR overrides the location outright, so an operator can relocate
// traces without a rebuild. Otherwise Pebble is placed next to a file-backed
// SQLite DB. An in-memory DSN gets a temp dir rather than the working directory:
// such a DB is ephemeral by definition, so persisting traces beside the CWD both
// outlives its own data and litters whichever directory the process (or a
// `go test` run) happens to start from.
func resolveTraceDir(databaseURL string, isSQLite bool) string {
	if dir := strings.TrimSpace(os.Getenv("GATEON_TRACE_DIR")); dir != "" {
		return dir
	}
	if !isSQLite {
		return "telemetry_pebble"
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
	pebbleOpts.EnsureDefaults()

	pdb, err := pebble.Open(pebbleDir, pebbleOpts)
	if err != nil {
		_ = database.Close()
		return fmt.Errorf("open pebble: %w", err)
	}

	st := &pathStatsStore{
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
	st.retentionDays.Store(int32(max(retentionDays, 1)))

	if cache, err := lru.NewARC(cacheSizeFromEnv(envScoreCacheSize, cacheNameScore, defaultScoreCacheSize)); err == nil {
		st.scoreCache = cache
	}
	if cache, err := lru.NewARC(cacheSizeFromEnv(envUnmitigatedCacheSize, cacheNameUnmitigated, defaultUnmitigatedCacheSize)); err == nil {
		st.unmitigatedCache = cache
	}
	if cache, err := lru.NewARC(cacheSizeFromEnv(envUserMitigatedCacheSize, cacheNameUserMitigated, defaultUserMitigatedCacheSize)); err == nil {
		st.userMitigationCache = cache
	}

	if err := db.Migrate(database, dialect); err != nil {
		_ = pdb.Close()
		_ = database.Close()
		return fmt.Errorf("failed to migrate database: %w", err)
	}

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
	for rows.Next() {
		var tr TraceRecord
		if err := rows.Scan(&tr.ID, &tr.OperationName, &tr.ServiceName, &tr.DurationMs, &tr.Timestamp, &tr.Status, &tr.Path, &tr.SourceIP, &tr.Fingerprint, &tr.CountryCode, &tr.UserAgent, &tr.Method, &tr.Referer, &tr.RequestURI, &tr.JA4, &tr.JA4H, &tr.RequestHeaders, &tr.RequestBody, &tr.ResponseHeaders, &tr.ResponseBody, &tr.RouteID, &tr.Recommendation, &tr.Reputation, &tr.EntrypointDelay, &tr.RouteDelay, &tr.MiddlewareDelay, &tr.ServiceDelay); err != nil {
			continue
		}

		key := makeTraceKey(tr.Timestamp, tr.ID)
		val, _ := json.Marshal(tr)
		_ = batch.Set(key, val, pebble.NoSync)

		n++
		if n%1000 == 0 {
			_ = batch.Commit(pebble.Sync)
			batch = s.pebble.NewBatch()
		}
	}
	_ = batch.Commit(pebble.Sync)

	logger.Default().LogInfo("telemetry: migration complete, clearing SQL traces table", "migrated", n)
	_, _ = s.db.Exec("DELETE FROM traces")
}

func makeTraceKey(ts time.Time, id string) []byte {
	k := make([]byte, 8+len(id)+1)
	binary.BigEndian.PutUint64(k[0:8], uint64(ts.UnixNano()))
	k[8] = ':'
	copy(k[9:], id)
	return k
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
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	// Initial seed - load current daily totals from the database into the
	// in-memory atomic counters. This ensures "Mitigated Today" and traffic
	// headline figures survive process restarts.
	s.syncDailyBaselines(false)

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
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
	if s.dialect.Driver == db.DriverMySQL {
		return tx.Prepare(QueryUpsertPathStatsMySQL)
	}
	q := s.dialect.Rebind(QueryUpsertPathStatsConflict)
	return tx.Prepare(q)
}

func (s *pathStatsStore) domainUpsertStmt(tx *sql.Tx) (*sql.Stmt, error) {
	if s.dialect.Driver == db.DriverMySQL {
		return tx.Prepare(QueryUpsertDomainStatsMySQL)
	}
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

	_, err := stmt.Exec(th.ID, th.Type, th.SourceIP, th.Fingerprint, th.Score, th.Details, th.Time,
		th.JA4, th.JA4H, th.RouteID, th.RequestURI, th.Category, th.Severity, th.ASN, th.ActionTaken,
		th.CountryCode, th.Latitude, th.Longitude, th.RequestHeaders, th.RequestBody,
		th.ResponseHeaders, th.ResponseBody, th.UserAgent, th.Method, th.Confidence, th.Entropy,
		th.ClusterSize, th.Recommendation, th.TriggeredRules, th.Reputation, sourceIPs)
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
		if len(batch) > 0 {
			tx, err := s.db.Begin()
			if err != nil {
				logger.Default().LogError("telemetry: begin transaction failed", "error", err)
			} else {
				defer tx.Rollback()
				pathStmt, _ := s.upsertStmt(tx)
				domainStmt, _ := s.domainUpsertStmt(tx)

				// Aggregate increments in the batch to reduce IOPS.
				// This significantly reduces the number of Exec() calls for popular paths.
				type aggKey struct {
					day      string
					host     string
					path     string
					isDomain bool
					bucket   int // for domain stats
				}
				aggregated := make(map[aggKey]*struct {
					count int
					latS  float64
					bytes uint64
				})

				for _, inc := range batch {
					day := inc.atTime.UTC().Format("2006-01-02")
					bucket := 0
					if inc.isDomain {
						// Use 30-minute buckets: hour*2 + (minute/30) -> 0-47
						bucket = inc.atTime.UTC().Hour()*2 + inc.atTime.UTC().Minute()/30
					}
					key := aggKey{day, inc.host, inc.path, inc.isDomain, bucket}

					if s, ok := aggregated[key]; ok {
						s.count++
						s.latS += inc.latS
						s.bytes += inc.bytesTotal
					} else {
						aggregated[key] = &struct {
							count int
							latS  float64
							bytes uint64
						}{1, inc.latS, inc.bytesTotal}
					}
				}

				for key, val := range aggregated {
					if key.isDomain {
						if domainStmt != nil {
							if _, err := domainStmt.Exec(key.day, key.bucket, key.host, val.count, val.latS, val.bytes); err != nil {
								logger.Default().LogError("domain stats: upsert failed", "error", err)
							}
						}
					} else {
						if pathStmt != nil {
							if _, err := pathStmt.Exec(key.day, key.host, key.path, val.count, val.latS, val.bytes); err != nil {
								logger.Default().LogError("path stats: upsert failed", "error", err)
							}
						}
					}
				}
				if pathStmt != nil {
					_ = pathStmt.Close()
				}
				if domainStmt != nil {
					_ = domainStmt.Close()
				}
				_ = tx.Commit()
			}
			batch = batch[:0]
		}

		if len(traceBatch) > 0 {
			batch := s.pebble.NewBatch()
			for _, tr := range traceBatch {
				key := makeTraceKey(tr.Timestamp, tr.ID)
				// Check for duplicates in a simple way for recent records if needed,
				// but for Pebble, Set just overwrites.
				// However, if we want strict ID uniqueness across all time, we'd need to check existence.
				// For access logs, the combination of timestamp (nano) and ID is extremely likely to be unique.
				val, _ := json.Marshal(tr)
				_ = batch.Set(key, val, pebble.NoSync)
			}
			if err := batch.Commit(pebble.Sync); err != nil {
				logger.Default().LogError("pebble: trace batch commit failed", "error", err)
			}
			for _, tr := range traceBatch {
				tr.Reset()
				tracePool.Put(tr)
			}
			traceBatch = traceBatch[:0]
		}

		if len(threatBatch) > 0 {
			tx, err := s.db.Begin()
			if err != nil {
				logger.Default().LogError("threats: begin transaction failed", "error", err)
			} else {
				defer tx.Rollback()
				if stmt, err := s.threatInsertStmt(tx); err == nil {
					for _, th := range threatBatch {
						sourceIPs := strings.Join(th.SourceIPs, ",")
						// Each row gets a savepoint so a single rejected threat
						// costs that threat and nothing else. Without it the
						// first failure aborts the surrounding transaction, and
						// on Postgres every later Exec then fails with 25P02 —
						// so one malformed record silently discarded the whole
						// batch. Threats are what the Security Hub is made of;
						// losing 127 good ones to a bad one is the difference
						// between a gap and a blind spot.
						if !s.execThreat(tx, stmt, th, sourceIPs) {
							logger.Default().LogWarn("threats: record dropped",
								"id", th.ID, "type", th.Type, "source_ip", th.SourceIP)
						}
					}
					_ = stmt.Close()
					if err := tx.Commit(); err != nil {
						logger.Default().LogError("threats: commit failed", "error", err)
					}
				}
				for _, th := range threatBatch {
					th.Reset()
					threatPool.Put(th)
				}
			}
			threatBatch = threatBatch[:0]
		}
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
			td := config.CurrentTierDefaults()
			interval := time.Duration(td.FlushIntervalSeconds) * time.Second
			if interval <= 0 {
				interval = 1 * time.Second
			}
			timer.Reset(interval)
		case ack := <-s.flushCh:
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

func (s *pathStatsStore) prune() {
	if s.pruning.Swap(true) {
		return
	}
	defer s.pruning.Store(false)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	s.prunePathAndDomainStats(ctx)
	s.pruneTraces()
	s.pruneSecurityThreats(ctx)
	s.pruneAuditLogs(ctx)

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
	days := s.effectiveRetention(s.accessLogRetentionDays.Load())
	if days <= 0 {
		return
	}
	cutoffTime := time.Now().AddDate(0, 0, -days)
	startKey := make([]byte, 8) // All zeros
	endKey := make([]byte, 8)
	binary.BigEndian.PutUint64(endKey, uint64(cutoffTime.UnixNano()))

	if err := s.pebble.DeleteRange(startKey, endKey, pebble.Sync); err != nil {
		logger.Default().LogError("pebble: prune failed", "error", err)
		return
	}
	// DeleteRange only writes tombstones; compact the pruned range to actually
	// reclaim disk space instead of waiting for an opportunistic compaction.
	if err := s.pebble.Compact(startKey, endKey, true); err != nil {
		logger.Default().LogError("pebble: compaction failed", "error", err)
	}
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
// It is a no-op for server databases (Postgres/MySQL) which manage their own
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
	// Format headers lazily in the background
	if tr.rawReqHeader != nil {
		tr.RequestHeaders = FormatHeaders(tr.rawReqHeader)
		tr.rawReqHeader = nil // Release map for GC
	}
	if tr.rawRespHeader != nil {
		tr.ResponseHeaders = FormatHeaders(tr.rawRespHeader)
		tr.rawRespHeader = nil // Release map for GC
	}

	// Redact sensitive headers in the background
	tr.RequestHeaders = RedactHeaders(tr.RequestHeaders)
	tr.ResponseHeaders = RedactHeaders(tr.ResponseHeaders)
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
	// Never record security threats for localhost to avoid flooding during tests
	// and management operations. Local loopback is trusted.
	if httputil.IsLoopback(t.SourceIP) {
		return
	}

	st := GetSecurityThreat()
	*st = t
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

func (s *pathStatsStore) processThreat(st *SecurityThreat) {
	// Format headers lazily in the background
	if st.rawReqHeader != nil {
		st.RequestHeaders = FormatHeaders(st.rawReqHeader)
		st.rawReqHeader = nil // Release for GC
	}
	if st.rawRespHeader != nil {
		st.ResponseHeaders = FormatHeaders(st.rawRespHeader)
		st.rawRespHeader = nil // Release for GC
	}

	// Redact sensitive data before persistence and broadcasting
	st.RequestHeaders = RedactHeaders(st.RequestHeaders)
	st.ResponseHeaders = RedactHeaders(st.ResponseHeaders)
	// We also redact the Details if it contains sensitive headers
	st.Details = RedactHeaders(st.Details)

	if st.ActionTaken == "" {
		st.ActionTaken = "detected"
	}
	st.Mitigated = st.ActionTaken == "blocked" || st.ActionTaken == "challenged" || st.ActionTaken == "shunned"
	if (st.Mitigated || st.Category == "reputation" || st.Score >= 80) &&
		st.Type != "user_mitigation" && st.Type != "ip_mitigation" && st.Type != "ip_shunning" {
		// Automatically mitigate fingerprints to ensure immediate blocking of the same actor.
		if st.Fingerprint != "" && !IsUserUnmitigated(st.Fingerprint) {
			MarkUserMitigated(st.Fingerprint, "JA4+", st.Details, st.Category)
		}

		// Escalation to IP Mitigation: 3-User Threshold
		if st.SourceIP != "" && st.Fingerprint != "" {
			ipMaliciousMu.Lock()
			val, _ := ipMaliciousFingerprints.Get(st.SourceIP)
			var fps map[string]struct{}
			if val != nil {
				fps = val.(map[string]struct{})
			} else {
				fps = make(map[string]struct{})
			}
			fps[st.Fingerprint] = struct{}{}
			ipMaliciousFingerprints.Add(st.SourceIP, fps)
			uniqueUsers := len(fps)
			ipMaliciousMu.Unlock()

			if uniqueUsers >= 3 && !IsIPUnmitigated(st.SourceIP) {
				MarkIPMitigated(st.SourceIP, fmt.Sprintf("IP shunning triggered: %d unique malicious users detected from this IP", uniqueUsers))
			}
		}
	}

	if st.CountryCode == "" && st.SourceIP != "" {
		st.CountryCode, _, st.Latitude, st.Longitude = ResolveIPInfoFast(st.SourceIP)
	}

	if st.ASN == "" && st.SourceIP != "" {
		st.ASN = ResolveASN(st.SourceIP)
	}

	// Log to audit trail
	audit.Log(context.Background(), "system", st.Type, st.RequestURI, fmt.Sprintf("Severity: %s, Details: %s, Action: %s", st.Severity, st.Details, st.ActionTaken), st.SourceIP)

	// Alerting and Broadcasting
	alertMu.RLock()
	h := onThreatAlert
	alertMu.RUnlock()
	if h != nil {
		h(st)
	}
	ThreatBroadcaster.Broadcast(*st)

	// funnel increments: map category/type to specific funnel counters
	isMitigated := st.Mitigated || st.ActionTaken == "blocked" || st.ActionTaken == "challenged" || st.ActionTaken == "shunned"
	if isMitigated {
		routeID := cmp.Or(st.RouteID, "global")
		cat := strings.ToLower(st.Category)
		typ := strings.ToLower(st.Type)

		switch {
		case cat == "waf" || typ == "waf_block" || typ == "waf_blocked" || typ == "waf_violation":
			ruleID := "unknown"
			if st.TriggeredRules != "" {
				ruleID = st.TriggeredRules
			} else if typ != "" {
				ruleID = typ
			}
			MiddlewareWAFBlockedTotal.WithLabelValues(routeID, ruleID).Inc()
		case strings.HasPrefix(typ, "fast_path_"):
			checkType := strings.TrimPrefix(typ, "fast_path_")
			MiddlewareFastPathBlockedTotal.WithLabelValues(routeID, checkType).Inc()
		case typ == "rate_limit" || cat == "abuse":
			MiddlewareRateLimitRejectedTotal.WithLabelValues(routeID, "behavioral").Inc()
		case cat == "deception" || typ == "honeypot_triggered" || typ == "honeypot_hit":
			trap := "unknown"
			if st.RequestURI != "" {
				trap = st.RequestURI
			}
			MiddlewareDeceptionBlockedTotal.WithLabelValues(routeID, trap).Inc()
		case typ == "reputation_hit" || typ == "advanced_security" || cat == "advanced" || cat == "threat_intel" || typ == "ip_mitigation" || typ == "user_mitigation":
			MiddlewareAdvancedSecurityBlockedTotal.WithLabelValues(routeID, typ).Inc()
		case cat == "geoip" || cat == "geofencing":
			MiddlewareGeoIPBlockedTotal.WithLabelValues(routeID, st.CountryCode).Inc()
		case cat == "auth" || typ == "brute_force_attempt":
			MiddlewareAuthFailuresTotal.WithLabelValues(routeID, typ).Inc()
		case cat == "bot":
			MiddlewareBotManagementTotal.WithLabelValues(routeID, "blocked").Inc()
		case cat == "filesecurity" || cat == "malware":
			MiddlewareFileSecurityBlockedTotal.WithLabelValues(routeID, typ).Inc()
		}
	}

	if s.scoreCache != nil {
		current, ok := s.scoreCache.Get(st.SourceIP)
		score := st.Score
		if ok {
			score += current.(float64)
		}
		s.scoreCache.Add(st.SourceIP, score)
	}

	repID := st.Fingerprint
	if repID == "" {
		repID = st.SourceIP
	}
	if repID != "" {
		DecreaseReputation(repID, st.Score/2, st.Type) // Penalty is half the threat score
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

// IsIPUnmitigated checks if an IP has been manually unmitigated by the user.
func IsIPUnmitigated(ip string) bool {
	s := getStore()
	if s == nil {
		return false
	}
	if s.unmitigatedCache != nil {
		if val, ok := s.unmitigatedCache.Get(ip); ok {
			return val.(bool)
		}
	}

	var status string
	query := s.dialect.Rebind("SELECT status FROM ip_mitigations WHERE ip = ?")
	err := s.db.QueryRow(query, ip).Scan(&status)
	if err != nil {
		return false
	}

	unmitigated := status == "unmitigated"
	if s.unmitigatedCache != nil {
		s.unmitigatedCache.Add(ip, unmitigated)
	}
	return unmitigated
}

// IsIPMitigated returns true if the IP is currently marked as mitigated in the store.
func IsIPMitigated(ip string) bool {
	s := getStore()
	if s == nil {
		return false
	}
	if s.unmitigatedCache != nil {
		if val, ok := s.unmitigatedCache.Get(ip); ok {
			return !val.(bool)
		}
	}

	var status string
	query := s.dialect.Rebind("SELECT status FROM ip_mitigations WHERE ip = ?")
	err := s.db.QueryRow(query, ip).Scan(&status)
	mitigated := false
	if err == nil && status == "mitigated" {
		mitigated = true
	}

	if s.unmitigatedCache != nil {
		s.unmitigatedCache.Add(ip, !mitigated)
	}
	return mitigated
}

// MarkIPMitigated records that an IP has been mitigated.
func MarkIPMitigated(ip string, reason string) {
	s := getStore()
	if s == nil {
		return
	}
	query := s.dialect.Rebind("INSERT INTO ip_mitigations (ip, status, reason, mitigated_at, updated_at) VALUES (?, 'mitigated', ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(ip) DO UPDATE SET status = 'mitigated', reason = ?, mitigated_at = ?, updated_at = CURRENT_TIMESTAMP")
	if s.dialect.Driver == db.DriverMySQL {
		query = "INSERT INTO ip_mitigations (ip, status, reason, mitigated_at) VALUES (?, 'mitigated', ?, ?) ON DUPLICATE KEY UPDATE status = 'mitigated', reason = ?, mitigated_at = ?, updated_at = CURRENT_TIMESTAMP"
	}
	now := time.Now()
	_, err := s.db.Exec(query, ip, reason, now, reason, now)
	if err != nil {
		logger.Default().LogError("failed to mark IP as mitigated", "ip", ip, "error", err)
	}
	if s.unmitigatedCache != nil {
		s.unmitigatedCache.Add(ip, false)
	}

	// Real-time eBPF synchronization for immediate effect at XDP layer
	if val := globalEbpfManager.Load(); val != nil {
		if container, ok := val.(*ebpfProviderContainer); ok && container.p != nil {
			_ = container.p.ShunIP(ip)
		}
	}
}

// MarkIPUnmitigated records that an IP has been manually unmitigated.
func MarkIPUnmitigated(ip string) {
	s := getStore()
	if s == nil {
		return
	}
	query := s.dialect.Rebind("UPDATE ip_mitigations SET status = 'unmitigated', unmitigated_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE ip = ?")
	_, err := s.db.Exec(query, ip)
	if err != nil {
		logger.Default().LogError("failed to mark IP as unmitigated", "ip", ip, "error", err)
	}
	if s.unmitigatedCache != nil {
		s.unmitigatedCache.Add(ip, true)
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
}

// GetMitigatedIPs returns a list of currently mitigated IPs (plain strings).
func GetMitigatedIPs(ctx context.Context) []string {
	s := getStore()
	if s == nil {
		return nil
	}
	query := s.dialect.Rebind("SELECT ip FROM ip_mitigations WHERE status = 'mitigated'")
	rows, err := s.db.QueryContext(ctx, query)
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

// GetIPMitigations returns a list of currently mitigated IPs with details.
func GetIPMitigations(ctx context.Context, limit, offset int) ([]IPMitigation, int) {
	s := getStore()
	if s == nil {
		return nil, 0
	}
	if limit <= 0 {
		limit = 50
	}

	countQuery := s.dialect.Rebind("SELECT COUNT(*) FROM ip_mitigations WHERE status = 'mitigated'")
	var total int
	if err := s.db.QueryRowContext(ctx, countQuery).Scan(&total); err != nil {
		return nil, 0
	}

	query := s.dialect.Rebind("SELECT ip, status, reason, mitigated_at, unmitigated_at, updated_at FROM ip_mitigations WHERE status = 'mitigated' ORDER BY mitigated_at DESC LIMIT ? OFFSET ?")
	ex, cleanup := s.getExecutor(ctx)
	defer cleanup()

	rows, err := ex.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, 0
	}
	defer rows.Close()

	var res []IPMitigation
	for rows.Next() {
		var m IPMitigation
		var mitigatedAt, updatedAt time.Time
		var unmitigatedAt sql.NullTime
		if err := rows.Scan(&m.IP, &m.Status, &m.Reason, &mitigatedAt, &unmitigatedAt, &updatedAt); err == nil {
			m.MitigatedAt = mitigatedAt
			m.UpdatedAt = updatedAt
			if unmitigatedAt.Valid {
				m.UnmitigatedAt = &unmitigatedAt.Time
			}
			res = append(res, m)
		}
	}
	return res, total
}

// IsUserMitigated returns true if the JA4+ fingerprint is currently marked as mitigated.
func IsUserMitigated(ja4plus string) bool {
	s := getStore()
	if s == nil || ja4plus == "" {
		return false
	}

	// 1. Check high-priority 'unmitigated' cache (Manual override / bypass)
	if s.unmitigatedCache != nil {
		if _, ok := s.unmitigatedCache.Get(ja4plus); ok {
			return false
		}
	}

	// 2. Check standard mitigation cache
	if s.userMitigationCache != nil {
		if val, ok := s.userMitigationCache.Get(ja4plus); ok {
			res := val.(bool)
			if res {
				// DOUBLE CHECK DB if cache says true, to avoid stale blocks after manual unmitigation.
				goto check_db
			}
			return false
		}
	}

check_db:
	// 3. Check DB for status 'mitigated'
	query := s.dialect.Rebind("SELECT status FROM user_mitigations WHERE (fingerprint = ? OR ja4h = ?) ORDER BY updated_at DESC LIMIT 1")
	var status string
	err := s.db.QueryRow(query, ja4plus, ja4plus).Scan(&status)
	mitigated := false
	if err == nil && status == "mitigated" {
		mitigated = true
	}

	if s.userMitigationCache != nil {
		s.userMitigationCache.Add(ja4plus, mitigated)
	}
	return mitigated
}

// IsUserUnmitigated returns true if the JA4+ fingerprint is currently explicitly unmitigated.
func IsUserUnmitigated(ja4plus string) bool {
	s := getStore()
	if s == nil || ja4plus == "" {
		return false
	}
	// Check DB for status 'unmitigated' within the last 24 hours to prevent immediate re-mitigation.
	query := s.dialect.Rebind("SELECT status FROM user_mitigations WHERE status = 'unmitigated' AND (fingerprint = ? OR ja4h = ?) AND updated_at > datetime('now', '-1 day')")
	var status string
	err := s.db.QueryRow(query, ja4plus, ja4plus).Scan(&status)
	return err == nil && status == "unmitigated"
}

// GetUserMitigations returns a list of currently mitigated users/fingerprints.
func GetUserMitigations(ctx context.Context, limit, offset int) ([]UserMitigation, int) {
	s := getStore()
	if s == nil {
		return nil, 0
	}
	if limit <= 0 {
		limit = 50
	}

	countQuery := s.dialect.Rebind("SELECT COUNT(*) FROM user_mitigations WHERE status = 'mitigated'")
	var total int
	if err := s.db.QueryRowContext(ctx, countQuery).Scan(&total); err != nil {
		return nil, 0
	}

	query := s.dialect.Rebind("SELECT fingerprint, ja4h, fp_type, status, reason, category, mitigated_at, unmitigated_at, updated_at FROM user_mitigations WHERE status = 'mitigated' ORDER BY mitigated_at DESC LIMIT ? OFFSET ?")
	ex, cleanup := s.getExecutor(ctx)
	defer cleanup()

	rows, err := ex.QueryContext(ctx, query, limit, offset)
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

	totalIPQuery := s.dialect.Rebind("SELECT COUNT(*) FROM ip_mitigations WHERE status = 'mitigated'")
	totalUserQuery := s.dialect.Rebind("SELECT COUNT(*) FROM user_mitigations WHERE status = 'mitigated'")

	var totalIP, totalUser int
	_ = s.db.QueryRowContext(ctx, totalIPQuery).Scan(&totalIP)
	_ = s.db.QueryRowContext(ctx, totalUserQuery).Scan(&totalUser)
	total := totalIP + totalUser

	// Use UNION ALL for consistent paging across both types.
	// Cast nulls to empty strings for consistency in scans.
	query := `
		SELECT 'ip' as source_type, ip as source, '' as ja4h, 'ip_shunning' as type, 'threat_intel' as category, status, reason, mitigated_at, unmitigated_at, updated_at
		FROM ip_mitigations
		WHERE status = 'mitigated'
		UNION ALL
		SELECT 'user' as source_type, fingerprint as source, ja4h, fp_type as type, category, status, reason, mitigated_at, unmitigated_at, updated_at
		FROM user_mitigations
		WHERE status = 'mitigated'
		ORDER BY mitigated_at DESC
		LIMIT ? OFFSET ?
	`
	query = s.dialect.Rebind(query)

	ex, cleanup := s.getExecutor(ctx)
	defer cleanup()

	rows, err := ex.QueryContext(ctx, query, limit, offset)
	if err != nil {
		logger.Default().LogError("failed to get combined mitigations", "error", err)
		return nil, 0
	}
	defer rows.Close()

	var res []CombinedMitigation
	for rows.Next() {
		var m CombinedMitigation
		var mitigatedAt, updatedAt time.Time
		var unmitigatedAt sql.NullTime
		var category sql.NullString
		if err := rows.Scan(&m.SourceType, &m.Source, &m.JA4H, &m.Type, &category, &m.Status, &m.Reason, &mitigatedAt, &unmitigatedAt, &updatedAt); err == nil {
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

// MarkUserMitigated records that a user fingerprint has been mitigated.
func MarkUserMitigated(ja4plus string, fpType string, reason string, category string) {
	s := getStore()
	if s == nil || ja4plus == "" {
		return
	}
	// We only use the fingerprint column for JA4+ suite. ja4h column is kept for schema compatibility but left empty.
	query := s.dialect.Rebind("INSERT INTO user_mitigations (fingerprint, ja4h, fp_type, status, reason, category, mitigated_at, updated_at) VALUES (?, '', ?, 'mitigated', ?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(fingerprint, ja4h) DO UPDATE SET status = 'mitigated', reason = ?, category = ?, mitigated_at = ?, updated_at = CURRENT_TIMESTAMP")
	if s.dialect.Driver == db.DriverMySQL {
		query = "INSERT INTO user_mitigations (fingerprint, ja4h, fp_type, status, reason, category, mitigated_at) VALUES (?, '', ?, 'mitigated', ?, ?, ?) ON DUPLICATE KEY UPDATE status = 'mitigated', reason = ?, category = ?, mitigated_at = ?, updated_at = CURRENT_TIMESTAMP"
	}

	now := time.Now()
	_, err := s.db.Exec(query, ja4plus, fpType, reason, category, now, reason, category, now)
	if err != nil {
		logger.Default().LogError("failed to mark user as mitigated", "ja4plus", ja4plus, "error", err)
	}
	if s.userMitigationCache != nil {
		s.userMitigationCache.Add(ja4plus, true)
	}
}

// MarkUserUnmitigated records that a fingerprint has been manually unmitigated.
func MarkUserUnmitigated(ja4plus string) {
	s := getStore()
	if s == nil || ja4plus == "" {
		return
	}
	// 1. Populate high-priority override cache (Bypass all security for 24h)
	if s.unmitigatedCache != nil {
		s.unmitigatedCache.Add(ja4plus, true)
	}

	// 2. FORCEFULLY update standard mitigation cache to 'false'
	if s.userMitigationCache != nil {
		s.userMitigationCache.Add(ja4plus, false)
	}

	// 3. Clear from DB and insert an explicit 'unmitigated' marker.
	queryDelete := s.dialect.Rebind("DELETE FROM user_mitigations WHERE fingerprint = ? OR ja4h = ?")
	_, _ = s.db.Exec(queryDelete, ja4plus, ja4plus)

	queryInsert := s.dialect.Rebind("INSERT INTO user_mitigations (fingerprint, ja4h, fp_type, status, reason, category, mitigated_at, unmitigated_at, updated_at) VALUES (?, 'UNMITIGATED_MARKER', 'JA4+', 'unmitigated', 'Manual reset', 'manual', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)")
	_, err := s.db.Exec(queryInsert, ja4plus)
	if err != nil {
		logger.Default().LogError("failed to mark user as unmitigated", "ja4plus", ja4plus, "error", err)
	}
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
			if err := unmarshalTraceSummary(iter.Value(), tr); err == nil {
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

// unmarshalTraceSummary unmarshals basic fields but omits heavy payloads.
func unmarshalTraceSummary(data []byte, tr *TraceRecord) error {
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
	}
	var s summary
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	tr.ID = s.ID
	tr.OperationName = s.OperationName
	tr.ServiceName = s.ServiceName
	tr.DurationMs = s.DurationMs
	tr.Timestamp = s.Timestamp
	tr.Status = s.Status
	tr.Path = s.Path
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
	th.Mitigated = th.ActionTaken == "blocked" || th.ActionTaken == "challenged" || th.ActionTaken == "shunned"
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
	if filter.Status == "mitigated" {
		// Mitigated if:
		// 1. Current status is 'mitigated' in IP or fingerprint table
		// 2. OR it was blocked at the time AND not subsequently unmitigated in any table
		conditions = append(conditions, fmt.Sprintf("(m.status = 'mitigated' OR fm4.status = 'mitigated' OR (%saction_taken IN ('blocked', 'challenged', 'shunned') AND (m.status IS NULL OR m.status != 'unmitigated') AND (fm4.status IS NULL OR fm4.status != 'unmitigated')))", prefix))
	} else if filter.Status == "detected" {
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
func FlushThreats() {
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

// GetSecurityThreats returns a paged list of security threats from the store.
func GetSecurityThreats(ctx context.Context, limit, offset int, filter *ThreatFilter) []*SecurityThreat {
	s := getStore()
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}

	where, args := buildThreatFilterQuery(s.dialect, filter, true)
	query := s.dialect.Rebind("SELECT t.id, t.type, t.source_ip, t.fingerprint, t.score, t.details, t.timestamp, t.ja4, t.ja4h, t.route_id, t.request_uri, t.category, t.severity, t.asn, t.action_taken, t.country_code, t.latitude, t.longitude, COALESCE(t.request_headers, ''), COALESCE(t.request_body, ''), COALESCE(t.response_headers, ''), COALESCE(t.response_body, ''), COALESCE(t.user_agent, ''), COALESCE(t.method, ''), t.confidence, t.entropy, t.cluster_size, COALESCE(t.recommendation, ''), COALESCE(t.triggered_rules, ''), t.reputation, COALESCE(m.status, ''), COALESCE(fm4.status, '') " +
		"FROM security_threats t LEFT JOIN ip_mitigations m ON t.source_ip = m.ip " +
		"LEFT JOIN user_mitigations fm4 ON t.ja4 = fm4.fingerprint AND (fm4.ja4h = '' OR fm4.ja4h = t.ja4h) " +
		where + " ORDER BY t.timestamp DESC LIMIT ? OFFSET ?")
	args = append(args, limit, offset)

	ex, cleanup := s.getExecutor(ctx)
	defer cleanup()

	rows, err := ex.QueryContext(ctx, query, args...)
	if err != nil {
		logQueryErr(ctx, "threats: query failed", err)
		return nil
	}
	defer rows.Close()
	res := make([]*SecurityThreat, 0, min(limit, 100))
	for rows.Next() {
		if ctx.Err() != nil {
			break
		}
		th := &SecurityThreat{}
		var mitigationStatus, fm4Status string
		if err := rows.Scan(&th.ID, &th.Type, &th.SourceIP, &th.Fingerprint, &th.Score, &th.Details, &th.Time, &th.JA4, &th.JA4H, &th.RouteID, &th.RequestURI, &th.Category, &th.Severity, &th.ASN, &th.ActionTaken, &th.CountryCode, &th.Latitude, &th.Longitude, &th.RequestHeaders, &th.RequestBody, &th.ResponseHeaders, &th.ResponseBody, &th.UserAgent, &th.Method, &th.Confidence, &th.Entropy, &th.ClusterSize, &th.Recommendation, &th.TriggeredRules, &th.Reputation, &mitigationStatus, &fm4Status); err != nil {
			logQueryErr(ctx, "threats: scan failed", err)
			continue
		}
		th.Mitigated = mitigationStatus == "mitigated" || fm4Status == "mitigated" ||
			((th.ActionTaken == "blocked" || th.ActionTaken == "challenged" || th.ActionTaken == "shunned") &&
				mitigationStatus != "unmitigated" && fm4Status != "unmitigated")
		res = append(res, th)
	}
	return res
}

// GetSecurityThreatsLite returns a paged list of recent security threats WITHOUT
// the heavyweight request/response header and body blobs. It is used on the hot
// dashboard-snapshot path (polled every couple of seconds), where those blobs are
// never rendered: fetching them needlessly scans four LONGTEXT columns per row,
// which under load blows the snapshot's request deadline ("threats: scan failed:
// context deadline exceeded") and bloats the SSE payload. The full-blob variant
// (GetSecurityThreats) remains for the detail/Threat-Explorer endpoint.
func GetSecurityThreatsLite(ctx context.Context, limit, offset int, filter *ThreatFilter) []*SecurityThreat {
	s := getStore()
	if s == nil {
		return nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}

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
	res := make([]*SecurityThreat, 0, min(limit, 100))
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
		th.Mitigated = mitigationStatus == "mitigated" || fm4Status == "mitigated" ||
			((th.ActionTaken == "blocked" || th.ActionTaken == "challenged" || th.ActionTaken == "shunned") &&
				mitigationStatus != "unmitigated" && fm4Status != "unmitigated")
		res = append(res, th)
	}
	return res
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

// attackTrendBucketQuery builds the threat-count trend query. Grouping by
// truncated timestamp is faster than grouping by formatted string.
func attackTrendBucketQuery(driver string, daily bool) string {
	isPostgres := driver == db.DriverPostgres || driver == "pgx"
	switch {
	case isPostgres && daily:
		return "SELECT date_trunc('day', timestamp) as bucket, COUNT(*) as cnt FROM security_threats WHERE timestamp >= ? GROUP BY bucket ORDER BY bucket ASC"
	case isPostgres:
		return "SELECT date_trunc('hour', timestamp) as bucket, COUNT(*) as cnt FROM security_threats WHERE timestamp >= ? GROUP BY bucket ORDER BY bucket ASC"
	case daily:
		// SQLite: date() is faster than strftime()
		return "SELECT date(timestamp) as bucket, COUNT(*) as cnt FROM security_threats WHERE timestamp >= ? GROUP BY bucket ORDER BY bucket ASC"
	default:
		// SQLite hourly
		return "SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as bucket, COUNT(*) as cnt FROM security_threats WHERE timestamp >= ? GROUP BY bucket ORDER BY bucket ASC"
	}
}

// GetAttackTrend returns a time-series of security threat counts.
func GetAttackTrend(ctx context.Context, days int) []TrafficSample {
	s := getStore()
	if s == nil {
		return nil
	}
	if days <= 0 {
		days = 1
	}
	cutoff := time.Now().Add(time.Duration(-days*24) * time.Hour).Format(threatTimestampLayout)
	query := attackTrendBucketQuery(s.dialect.Driver, days > attackTrendDailyThresholdDays)

	ex, cleanup := s.getExecutor(ctx)
	defer cleanup()

	rows, err := ex.QueryContext(ctx, s.dialect.Rebind(query), cutoff)
	if err != nil {
		return nil
	}
	defer rows.Close()

	res := make([]TrafficSample, 0, 48) // typical dashboard view
	for rows.Next() {
		var bucket any
		var count uint64
		if err := rows.Scan(&bucket, &count); err != nil {
			continue
		}

		var t time.Time
		switch v := bucket.(type) {
		case time.Time:
			t = v
		case string:
			// SQLite/MySQL return strings
			if len(v) > 19 {
				v = v[:19]
			}
			t, _ = time.Parse("2006-01-02 15:04:05", v)
			if t.IsZero() {
				t, _ = time.Parse("2006-01-02", v)
			}
		}

		if !t.IsZero() {
			res = append(res, TrafficSample{
				Timestamp: t.UnixMilli(),
				Requests:  count,
			})
		}
	}
	return res
}
