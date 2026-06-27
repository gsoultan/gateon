package telemetry

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
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
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/syncutil"
	lru "github.com/hashicorp/golang-lru"
)

// AlertingHandler is a function type for alerting integration.
type AlertingHandler func(*SecurityThreat)

var (
	onThreatAlert AlertingHandler
	alertMu       sync.RWMutex

	ThreatBroadcaster = &Broadcaster[SecurityThreat]{
		subscribers: make(map[chan SecurityThreat]struct{}),
	}
)

type Broadcaster[T any] struct {
	mu          sync.RWMutex
	subscribers map[chan T]struct{}
}

func (b *Broadcaster[T]) Subscribe() chan T {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan T, 10)
	b.subscribers[ch] = struct{}{}
	return ch
}

func (b *Broadcaster[T]) Unsubscribe(ch chan T) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.subscribers, ch)
	close(ch)
}

func (b *Broadcaster[T]) Broadcast(data T) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.subscribers {
		select {
		case ch <- data:
		default:
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
	storeMu sync.Mutex
)

type increment struct {
	host       string
	path       string
	latS       float64
	bytesTotal uint64
	atTime     time.Time
	isDomain   bool
}

type TraceRecord struct {
	ID              string    `json:"id"`
	OperationName   string    `json:"operation_name"`
	ServiceName     string    `json:"service_name"`
	DurationMs      float64   `json:"duration_ms"`
	Timestamp       time.Time `json:"timestamp,omitzero"`
	Status          string    `json:"status"`
	Path            string    `json:"path"`
	SourceIP        string    `json:"source_ip"`
	Fingerprint     string    `json:"fingerprint"`
	CountryCode     string    `json:"country_code"`
	UserAgent       string    `json:"user_agent"`
	Method          string    `json:"method"`
	Referer         string    `json:"referer"`
	RequestURI      string    `json:"request_uri"`
	JA3             string    `json:"ja3"`
	RequestHeaders  string    `json:"request_headers"`
	RequestBody     string    `json:"request_body"`
	ResponseHeaders string    `json:"response_headers"`
	ResponseBody    string    `json:"response_body"`
	JA4             string    `json:"ja4"`
	RouteID         string    `json:"route_id"`
}

type SecurityThreat struct {
	ID              string    `json:"id"`
	Type            string    `json:"type"`
	SourceIP        string    `json:"source_ip"`
	Fingerprint     string    `json:"fingerprint"`
	Score           float64   `json:"score"`
	Details         string    `json:"details"`
	Time            time.Time `json:"timestamp,omitzero"`
	JA3             string    `json:"ja3"`
	JA4             string    `json:"ja4"`
	RouteID         string    `json:"route_id"`
	RequestURI      string    `json:"request_uri"`
	Category        string    `json:"category"`
	Severity        string    `json:"severity"`
	ASN             string    `json:"asn"`
	ActionTaken     string    `json:"action_taken"`
	CountryCode     string    `json:"country_code"`
	Mitigated       bool      `json:"mitigated"`
	RequestHeaders  string    `json:"request_headers"`
	RequestBody     string    `json:"request_body"`
	ResponseHeaders string    `json:"response_headers"`
	ResponseBody    string    `json:"response_body"`
	UserAgent       string    `json:"user_agent"`
	Method          string    `json:"method"`
}

type pathStatsStore struct {
	db                          *sql.DB
	pebble                      *pebble.DB
	dialect                     db.Dialect
	inCh                        chan increment
	traceInCh                   chan TraceRecord
	threatInCh                  chan SecurityThreat
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
	traceStoreEnabled           bool

	// Real-time daily counters
	baselineReqToday       atomic.Uint64
	baselineBytesToday     atomic.Uint64
	baselineActiveToday    atomic.Uint64
	baselineMitigatedToday atomic.Uint64
	currentReqToday        atomic.Uint64
	currentBytesToday      atomic.Uint64
	currentActiveToday     atomic.Uint64
	currentMitigatedToday  atomic.Uint64
	lastResetDay           string
	resetMu                sync.Mutex
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

	// Initialize Pebble for traces
	pebbleDir := "telemetry_pebble"
	if dialect.Driver == db.DriverSQLite {
		// Place Pebble next to SQLite db if it's a file
		if !filepath.IsAbs(databaseURL) && !strings.Contains(databaseURL, "://") {
			pebbleDir = filepath.Join(filepath.Dir(databaseURL), "telemetry_pebble")
		}
	}
	_ = os.MkdirAll(pebbleDir, 0755)

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
	for i := range pebbleOpts.Levels {
		pebbleOpts.Levels[i].Compression = pebble.ZstdCompression
	}

	pdb, err := pebble.Open(pebbleDir, pebbleOpts)
	if err != nil {
		_ = database.Close()
		return fmt.Errorf("open pebble: %w", err)
	}

	st := &pathStatsStore{
		db:                database,
		pebble:            pdb,
		dialect:           dialect,
		inCh:              make(chan increment, 4096),
		traceInCh:         make(chan TraceRecord, 4096),
		threatInCh:        make(chan SecurityThreat, 1024),
		stopCh:            make(chan struct{}),
		traceStoreEnabled: td.TraceStoreEnabled,
	}
	st.retentionDays.Store(int32(max(retentionDays, 1)))

	if cache, err := lru.NewARC(cacheSizeFromEnv(envScoreCacheSize, cacheNameScore, defaultScoreCacheSize)); err == nil {
		st.scoreCache = cache
	}
	if cache, err := lru.NewARC(cacheSizeFromEnv(envUnmitigatedCacheSize, cacheNameUnmitigated, defaultUnmitigatedCacheSize)); err == nil {
		st.unmitigatedCache = cache
	}

	if err := db.Migrate(database, dialect); err != nil {
		_ = pdb.Close()
		_ = database.Close()
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	// Migration: Move existing traces from SQL to Pebble if table exists.
	// Skipped when the trace store is disabled by the resource profile.
	if st.traceStoreEnabled {
		go st.migrateTracesToPebble()
	}

	// Restore volatile security counters from persisted history so the
	// dashboard reflects past activity instead of resetting to 0 on restart.
	go st.restoreWAFBlockCounter()

	st.wg.Go(st.loop)
	st.wg.Go(st.dailyResetLoop)

	store = st
	return nil
}

func (s *pathStatsStore) migrateTracesToPebble() {
	// Check if traces table has data
	var count int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM traces").Scan(&count)
	if count == 0 {
		return
	}

	logger.Default().LogInfo("telemetry: migrating existing traces to Pebble", "count", count)

	rows, err := s.db.Query("SELECT id, operation_name, service_name, duration_ms, timestamp, status, path, source_ip, fingerprint, country_code, COALESCE(user_agent, ''), COALESCE(method, ''), COALESCE(referer, ''), COALESCE(request_uri, ''), COALESCE(ja3, ''), COALESCE(ja4, ''), COALESCE(request_headers, ''), COALESCE(request_body, ''), COALESCE(response_headers, ''), COALESCE(response_body, '') FROM traces")
	if err != nil {
		return
	}
	defer rows.Close()

	batch := s.pebble.NewBatch()
	n := 0
	for rows.Next() {
		var tr TraceRecord
		if err := rows.Scan(&tr.ID, &tr.OperationName, &tr.ServiceName, &tr.DurationMs, &tr.Timestamp, &tr.Status, &tr.Path, &tr.SourceIP, &tr.Fingerprint, &tr.CountryCode, &tr.UserAgent, &tr.Method, &tr.Referer, &tr.RequestURI, &tr.JA3, &tr.JA4, &tr.RequestHeaders, &tr.RequestBody, &tr.ResponseHeaders, &tr.ResponseBody); err != nil {
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

	logger.Default().LogInfo("telemetry: migration complete, dropping SQL traces table", "migrated", n)
	_, _ = s.db.Exec("DROP TABLE traces")
}

func makeTraceKey(ts time.Time, id string) []byte {
	k := make([]byte, 8+len(id)+1)
	binary.BigEndian.PutUint64(k[0:8], uint64(ts.UnixNano()))
	k[8] = ':'
	copy(k[9:], id)
	return k
}

func (s *pathStatsStore) dailyResetLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	// Initial sync - load baselines but don't reset current counters
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
				// Day changed!
				s.syncDailyBaselines(true)
			}
			s.lastResetDay = day
			s.resetMu.Unlock()
		}
	}
}

func (s *pathStatsStore) syncDailyBaselines(resetCurrent bool) {
	now := time.Now().UTC()
	day := now.Format("2006-01-02")
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	// Traffic baselines
	q := s.dialect.Rebind(QueryGetTotalTrafficToday)
	var rc, bsum sql.NullInt64
	err := s.db.QueryRow(q, day).Scan(&rc, &bsum)
	if err != nil {
		s.baselineReqToday.Store(0)
		s.baselineBytesToday.Store(0)
	} else {
		s.baselineReqToday.Store(uint64(rc.Int64))
		s.baselineBytesToday.Store(uint64(bsum.Int64))
	}

	// Active threats baseline. security_threats.timestamp is a TIMESTAMP column
	// persisted from a time.Time, so it must be compared against a datetime
	// string (matching GetAttackTrend) rather than an integer Unix value.
	qThreats := s.dialect.Rebind(QueryGetActiveThreatsToday)
	var activeCount int64
	err = s.db.QueryRow(qThreats, startOfDay.Format(threatTimestampLayout)).Scan(&activeCount)
	if err != nil {
		s.baselineActiveToday.Store(0)
	} else {
		s.baselineActiveToday.Store(uint64(activeCount))
	}

	// Mitigated threats baseline (today's blocked/challenged/shunned actions),
	// mirroring the active-threats baseline so "Mitigated Today" survives
	// process restarts instead of resetting to 0.
	qMitigated := s.dialect.Rebind(QueryGetMitigatedThreatsToday)
	var mitigatedCount int64
	err = s.db.QueryRow(qMitigated, startOfDay.Format(threatTimestampLayout)).Scan(&mitigatedCount)
	if err != nil {
		s.baselineMitigatedToday.Store(0)
	} else {
		s.baselineMitigatedToday.Store(uint64(mitigatedCount))
	}

	if !resetCurrent {
		return
	}

	s.currentReqToday.Store(0)
	s.currentBytesToday.Store(0)
	s.currentActiveToday.Store(0)
	s.currentMitigatedToday.Store(0)

	// Reset global telemetry structures for the new day
	GlobalCMS.Clear()
	GlobalHHH.Clear()
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
	q := s.dialect.Rebind("INSERT INTO security_threats (id, type, source_ip, fingerprint, score, details, timestamp, ja3, ja4, route_id, request_uri, category, severity, asn, action_taken, country_code, request_headers, request_body, response_headers, response_body, user_agent, method) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	return tx.Prepare(q)
}

func (s *pathStatsStore) loop() {
	flushTicker := time.NewTicker(1 * time.Second)
	pruneTicker := time.NewTicker(1 * time.Hour)
	defer flushTicker.Stop()
	defer pruneTicker.Stop()

	batch := make([]increment, 0, 1024)
	traceBatch := make([]TraceRecord, 0, 1024)
	threatBatch := make([]SecurityThreat, 0, 128)

	flush := func() {
		if len(batch) > 0 {
			tx, err := s.db.Begin()
			if err != nil {
				logger.Default().LogError("telemetry: begin transaction failed", "error", err)
			} else {
				pathStmt, _ := s.upsertStmt(tx)
				domainStmt, _ := s.domainUpsertStmt(tx)

				for _, inc := range batch {
					if inc.isDomain {
						if domainStmt != nil {
							day := inc.atTime.UTC().Format("2006-01-02")
							// Use 30-minute buckets: hour*2 + (minute/30) -> 0-47
							bucket := inc.atTime.UTC().Hour()*2 + inc.atTime.UTC().Minute()/30
							if _, err := domainStmt.Exec(day, bucket, inc.host, 1, inc.latS, inc.bytesTotal); err != nil {
								logger.Default().LogError("domain stats: upsert failed", "error", err)
							}
						}
					} else {
						if pathStmt != nil {
							day := inc.atTime.UTC().Format("2006-01-02")
							if _, err := pathStmt.Exec(day, inc.host, inc.path, 1, inc.latS, inc.bytesTotal); err != nil {
								logger.Default().LogError("path stats: upsert failed", "error", err)
							}
						}
					}
				}
				if pathStmt != nil {
					pathStmt.Close()
				}
				if domainStmt != nil {
					domainStmt.Close()
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
			traceBatch = traceBatch[:0]
		}

		if len(threatBatch) > 0 {
			tx, err := s.db.Begin()
			if err != nil {
				logger.Default().LogError("threats: begin transaction failed", "error", err)
			} else {
				if stmt, err := s.threatInsertStmt(tx); err == nil {
					for _, th := range threatBatch {
						if _, err := stmt.Exec(th.ID, th.Type, th.SourceIP, th.Fingerprint, th.Score, th.Details, th.Time, th.JA3, th.JA4, th.RouteID, th.RequestURI, th.Category, th.Severity, th.ASN, th.ActionTaken, th.CountryCode, th.RequestHeaders, th.RequestBody, th.ResponseHeaders, th.ResponseBody, th.UserAgent, th.Method); err != nil {
							logger.Default().LogError("threats: insert failed", "error", err)
						}
					}
					stmt.Close()
					_ = tx.Commit()
				} else {
					_ = tx.Rollback()
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
			traceBatch = append(traceBatch, tr)
			if len(traceBatch) >= cap(traceBatch) {
				flush()
			}
		case th := <-s.threatInCh:
			threatBatch = append(threatBatch, th)
			if len(threatBatch) >= cap(threatBatch) {
				flush()
			}
		case <-flushTicker.C:
			flush()
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
	defer storeMu.Unlock()
	if store == nil {
		return nil
	}
	s := store
	store = nil

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
	if store == nil {
		return
	}
	if days <= 0 {
		days = 1
	}
	store.retentionDays.Store(int32(days))
}

func ConfigureGranularRetention(pathStats, accessLog, securityThreat, auditLog int) {
	if store == nil {
		return
	}
	store.pathStatsRetentionDays.Store(int32(pathStats))
	store.accessLogRetentionDays.Store(int32(accessLog))
	store.securityThreatRetentionDays.Store(int32(securityThreat))
	store.auditLogRetentionDays.Store(int32(auditLog))
}

// recordToStore attempts to enqueue an increment; if the store is not initialized or channel is full, it drops silently to avoid impacting the hot path.
func recordToStore(host, path string, latencySeconds float64, bytesTotal uint64, at time.Time) {
	if store == nil {
		return
	}
	select {
	case store.inCh <- increment{host: host, path: path, latS: latencySeconds, bytesTotal: bytesTotal, atTime: at, isDomain: false}:
		// No need to update currentReqToday here as it's done in recordDomainToStore for total traffic
	default:
		// drop on backpressure to protect the request path
	}
}

// recordDomainToStore attempts to enqueue an increment for a domain.
func recordDomainToStore(domain string, latencySeconds float64, bytesTotal uint64, at time.Time) {
	if store == nil {
		return
	}
	select {
	case store.inCh <- increment{host: domain, latS: latencySeconds, bytesTotal: bytesTotal, atTime: at, isDomain: true}:
		store.currentReqToday.Add(1)
		store.currentBytesToday.Add(bytesTotal)
	default:
		// drop on backpressure
	}
}

// recordTraceToStore attempts to enqueue a trace record.
func recordTraceToStore(id, operationName, serviceName, routeID string, durationMs float64, timestamp time.Time, status, path, sourceIP, fingerprint, countryCode, userAgent, method, referer, requestURI, ja3, ja4, reqHeaders, reqBody, respHeaders, respBody string) {
	if store == nil || !store.traceStoreEnabled {
		return
	}
	select {
	case store.traceInCh <- TraceRecord{
		ID:              id,
		OperationName:   operationName,
		ServiceName:     serviceName,
		RouteID:         routeID,
		DurationMs:      durationMs,
		Timestamp:       timestamp,
		Status:          status,
		Path:            path,
		SourceIP:        sourceIP,
		Fingerprint:     fingerprint,
		CountryCode:     countryCode,
		UserAgent:       userAgent,
		Method:          method,
		Referer:         referer,
		RequestURI:      requestURI,
		JA3:             ja3,
		JA4:             ja4,
		RequestHeaders:  reqHeaders,
		RequestBody:     reqBody,
		ResponseHeaders: respHeaders,
		ResponseBody:    respBody,
	}:
	default:
		// drop on backpressure
	}
}

// RecordSecurityThreat attempts to enqueue a security threat.
func RecordSecurityThreat(t SecurityThreat) {
	if store == nil {
		return
	}
	if t.ID == "" {
		t.ID = uuid.NewString()
	}
	if t.Time.IsZero() {
		t.Time = time.Now()
	}

	if t.ActionTaken == "" {
		t.ActionTaken = "detected"
	}
	t.Mitigated = t.ActionTaken == "blocked" || t.ActionTaken == "challenged" || t.ActionTaken == "shunned"

	if t.CountryCode == "" && t.SourceIP != "" {
		t.CountryCode = ResolveCountry(t.SourceIP)
	}

	if t.ASN == "" && t.SourceIP != "" {
		t.ASN = ResolveASN(t.SourceIP)
	}

	if store.scoreCache != nil {
		current, ok := store.scoreCache.Get(t.SourceIP)
		score := t.Score
		if ok {
			score += current.(float64)
		}
		store.scoreCache.Add(t.SourceIP, score)
	}

	repID := t.Fingerprint
	if repID == "" {
		repID = t.SourceIP
	}
	if repID != "" {
		DecreaseReputation(repID, t.Score/2, t.Type) // Penalty is half the threat score
	}

	// Update global telemetry structures
	GlobalCMS.AddWeighted("global", uint32(t.Score))
	if t.SourceIP != "" {
		GlobalHHH.Add(t.SourceIP)
	}

	// Increment Prometheus counter
	if t.Mitigated {
		MitigatedThreatsTotal.WithLabelValues(cmp.Or(t.Category, "general"), cmp.Or(t.Severity, "medium"), cmp.Or(t.ActionTaken, "blocked")).Inc()
		store.currentMitigatedToday.Add(1)
	} else {
		ActiveThreatsTotal.WithLabelValues(cmp.Or(t.Category, "general"), cmp.Or(t.Severity, "medium")).Inc()
		store.currentActiveToday.Add(1)
	}

	alertMu.RLock()
	h := onThreatAlert
	alertMu.RUnlock()
	if h != nil {
		h(&t)
	}

	ThreatBroadcaster.Broadcast(t)

	select {
	case store.threatInCh <- t:
	default:
		// drop on backpressure
	}

	// Log to audit trail
	audit.Log(context.Background(), "system", "security_threat", t.RequestURI, fmt.Sprintf("Type: %s, Severity: %s, Details: %s, Action: %s", t.Type, t.Severity, t.Details, t.ActionTaken), t.SourceIP)
}

// GetIPThreatScore returns the current security threat score for an IP.
func GetIPThreatScore(ip string) float64 {
	if store == nil || store.scoreCache == nil {
		return 0
	}
	if val, ok := store.scoreCache.Get(ip); ok {
		return val.(float64)
	}
	return 0
}

// IsIPUnmitigated checks if an IP has been manually unmitigated by the user.
func IsIPUnmitigated(ip string) bool {
	if store == nil {
		return false
	}
	if store.unmitigatedCache != nil {
		if val, ok := store.unmitigatedCache.Get(ip); ok {
			return val.(bool)
		}
	}

	var status string
	query := store.dialect.Rebind("SELECT status FROM ip_mitigations WHERE ip = ?")
	err := store.db.QueryRow(query, ip).Scan(&status)
	if err != nil {
		return false
	}

	unmitigated := status == "unmitigated"
	if store.unmitigatedCache != nil {
		store.unmitigatedCache.Add(ip, unmitigated)
	}
	return unmitigated
}

// MarkIPMitigated records that an IP has been mitigated.
func MarkIPMitigated(ip string, reason string) {
	if store == nil {
		return
	}
	query := store.dialect.Rebind("INSERT INTO ip_mitigations (ip, status, reason, mitigated_at, updated_at) VALUES (?, 'mitigated', ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(ip) DO UPDATE SET status = 'mitigated', reason = ?, mitigated_at = ?, updated_at = CURRENT_TIMESTAMP")
	if store.dialect.Driver == db.DriverMySQL {
		query = "INSERT INTO ip_mitigations (ip, status, reason, mitigated_at) VALUES (?, 'mitigated', ?, ?) ON DUPLICATE KEY UPDATE status = 'mitigated', reason = ?, mitigated_at = ?, updated_at = CURRENT_TIMESTAMP"
	}
	now := time.Now()
	_, err := store.db.Exec(query, ip, reason, now, reason, now)
	if err != nil {
		logger.Default().LogError("failed to mark IP as mitigated", "ip", ip, "error", err)
	}
	if store.unmitigatedCache != nil {
		store.unmitigatedCache.Add(ip, false)
	}
}

// MarkIPUnmitigated records that an IP has been manually unmitigated.
func MarkIPUnmitigated(ip string) {
	if store == nil {
		return
	}
	query := store.dialect.Rebind("UPDATE ip_mitigations SET status = 'unmitigated', unmitigated_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE ip = ?")
	_, err := store.db.Exec(query, ip)
	if err != nil {
		logger.Default().LogError("failed to mark IP as unmitigated", "ip", ip, "error", err)
	}
	if store.unmitigatedCache != nil {
		store.unmitigatedCache.Add(ip, true)
	}
}

// GetMitigatedIPs returns a list of currently mitigated IPs.
func GetMitigatedIPs(ctx context.Context) []string {
	if store == nil {
		return nil
	}
	query := store.dialect.Rebind("SELECT ip FROM ip_mitigations WHERE status = 'mitigated'")
	rows, err := store.db.QueryContext(ctx, query)
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

// GetTraces returns the last N traces from the store.
func GetTraces(ctx context.Context, limit int) []TraceRecord {
	if store == nil || store.pebble == nil {
		return nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	iter, _ := store.pebble.NewIter(&pebble.IterOptions{})
	defer iter.Close()

	res := make([]TraceRecord, 0, min(limit, 100))
	seen := make(map[string]struct{})

	// Start from the end (most recent)
	for ok := iter.Last(); ok && len(res) < limit; ok = iter.Prev() {
		var tr TraceRecord
		if err := json.Unmarshal(iter.Value(), &tr); err == nil {
			if _, ok := seen[tr.ID]; ok {
				continue
			}
			seen[tr.ID] = struct{}{}
			res = append(res, tr)
		}
	}
	return res
}

// GetPathStatsWindow returns aggregated stats from storage for the last `days` days.
// Falls back to in-memory stats on DB errors to ensure metrics are always available.
func GetPathStatsWindow(ctx context.Context, days int) []PathStats {
	if store == nil {
		return getInMemoryPathStats()
	}
	if days <= 0 {
		days = int(store.retentionDays.Load())
	}
	cutoff := time.Now().AddDate(0, 0, -days+1).UTC().Format("2006-01-02")
	q := store.dialect.Rebind(QueryGetPathStatsWin)
	rows, err := store.db.QueryContext(ctx, q, cutoff)
	if err != nil {
		logger.Default().LogError("path stats: DB query failed, falling back to in-memory stats", "error", err)
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
			Host:         host,
			Path:         p,
			RequestCount: uint64(rc),
			BytesTotal:   uint64(max(bsum, 0)),
			LatencySum:   lsum,
			AvgLatency:   float64(int(avg*1000+0.5)) / 1000.0,
		})
	}
	return res
}

// GetDomainStatsWindow returns aggregated domain statistics for the last N days.
func GetDomainStatsWindow(ctx context.Context, days int) []DomainStats {
	if store == nil {
		return nil
	}
	if days <= 0 {
		days = int(store.retentionDays.Load())
	}
	cutoff := time.Now().AddDate(0, 0, -days+1).UTC().Format("2006-01-02")
	q := store.dialect.Rebind(QueryGetDomainStatsWin)
	rows, err := store.db.QueryContext(ctx, q, cutoff)
	if err != nil {
		logger.Default().LogError("domain stats: query failed", "error", err)
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
			Domain:       domain,
			RequestCount: uint64(rc),
			BytesTotal:   uint64(max(bsum, 0)),
			LatencySum:   lsum,
			AvgLatency:   float64(int(avg*1000+0.5)) / 1000.0,
		})
	}
	return stats
}

// GetSystemTrafficToday returns total requests and bandwidth for the current day.
func GetSystemTrafficToday(ctx context.Context) (uint64, uint64) {
	if store == nil {
		return 0, 0
	}
	return store.baselineReqToday.Load() + store.currentReqToday.Load(),
		store.baselineBytesToday.Load() + store.currentBytesToday.Load()
}

// GetSystemTrafficHistory returns traffic samples for the last N days.
func GetSystemTrafficHistory(ctx context.Context, days int) []TrafficSample {
	if store == nil {
		return nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02")
	// For long spans collapse each day into a single bucket so the result set
	// stays small (bounded memory and snapshot size).
	query := QueryGetTrafficHistory
	if days > trafficDailyAggregationThresholdDays {
		query = QueryGetTrafficHistoryDaily
	}
	q := store.dialect.Rebind(query)
	rows, err := store.db.QueryContext(ctx, q, cutoff)
	if err != nil {
		logger.Default().LogError("traffic history: query failed", "error", err)
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
		logger.Default().LogError("traffic history: rows error", "error", err)
	}
	return samples
}

// GetDomainStatsHourly returns domain statistics for a specific hour.
func GetDomainStatsHourly(day string, hour int) []DomainStats {
	if store == nil {
		return nil
	}
	q := store.dialect.Rebind(QueryGetDomainStatsHourly)
	rows, err := store.db.Query(q, day, hour)
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
			Domain:       domain,
			Hour:         hr,
			RequestCount: uint64(rc),
			BytesTotal:   uint64(max(bsum, 0)),
			LatencySum:   lsum,
			AvgLatency:   float64(int(avg*1000+0.5)) / 1000.0,
		})
	}
	return stats
}

// GetActiveThreatsToday returns the count of active threats for the current day.
func GetActiveThreatsToday() uint64 {
	if store == nil {
		return 0
	}
	return store.baselineActiveToday.Load() + store.currentActiveToday.Load()
}

// GetMitigatedToday returns the count of threats actively mitigated
// (blocked/challenged/shunned) for the current day. The baseline is seeded
// from the database at startup and on each day rollover, so the figure
// survives process restarts.
func GetMitigatedToday() uint64 {
	if store == nil {
		return 0
	}
	return store.baselineMitigatedToday.Load() + store.currentMitigatedToday.Load()
}

// GetSecurityThreats returns a paged list of security threats from the store.
func GetSecurityThreats(ctx context.Context, limit, offset int) []SecurityThreat {
	if store == nil {
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
	query := store.dialect.Rebind("SELECT id, type, source_ip, fingerprint, score, details, timestamp, ja3, ja4, route_id, request_uri, category, severity, asn, action_taken, country_code, COALESCE(request_headers, ''), COALESCE(request_body, ''), COALESCE(response_headers, ''), COALESCE(response_body, ''), COALESCE(user_agent, ''), COALESCE(method, '') FROM security_threats ORDER BY timestamp DESC LIMIT ? OFFSET ?")
	rows, err := store.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		logger.Default().LogError("threats: query failed", "error", err)
		return nil
	}
	defer rows.Close()
	res := make([]SecurityThreat, 0, min(limit, 100))
	for rows.Next() {
		var th SecurityThreat
		if err := rows.Scan(&th.ID, &th.Type, &th.SourceIP, &th.Fingerprint, &th.Score, &th.Details, &th.Time, &th.JA3, &th.JA4, &th.RouteID, &th.RequestURI, &th.Category, &th.Severity, &th.ASN, &th.ActionTaken, &th.CountryCode, &th.RequestHeaders, &th.RequestBody, &th.ResponseHeaders, &th.ResponseBody, &th.UserAgent, &th.Method); err != nil {
			logger.Default().LogError("threats: scan failed", "error", err)
			continue
		}
		th.Mitigated = th.ActionTaken == "blocked" || th.ActionTaken == "challenged" || th.ActionTaken == "shunned"
		res = append(res, th)
	}
	return res
}

// CountSecurityThreats returns the total number of security threats in the store.
func CountSecurityThreats(ctx context.Context) int64 {
	if store == nil {
		return 0
	}
	var count int64
	query := store.dialect.Rebind("SELECT COUNT(*) FROM security_threats")
	err := store.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0
	}
	return count
}

func IsStoreEnabled() bool {
	return store != nil
}

// PingStore checks the health of the telemetry database.
func PingStore(ctx context.Context) error {
	if store == nil {
		return fmt.Errorf("telemetry store not initialized")
	}
	return store.db.PingContext(ctx)
}

// CurrentRetentionDays returns the active retention configuration.
func CurrentRetentionDays() int {
	if store == nil {
		return 0
	}
	return int(store.retentionDays.Load())
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
		days = 1
	}
	return min(days, maxDashboardTrendWindowDays)
}

// GetTopThreatSources returns the most frequent attacking IP addresses.
func GetTopThreatSources(ctx context.Context, limit int) []LabeledCount {
	if store == nil {
		return nil
	}
	query := store.dialect.Rebind("SELECT source_ip, COALESCE(MAX(asn), ''), COUNT(*) as cnt FROM security_threats GROUP BY source_ip ORDER BY cnt DESC LIMIT ?")
	rows, err := store.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var res []LabeledCount
	for rows.Next() {
		var label string
		var asn string
		var count float64
		if err := rows.Scan(&label, &asn, &count); err != nil {
			logger.Default().LogError("top threat sources: scan failed", "error", err)
			continue
		}
		res = append(res, LabeledCount{Label: label, Value: count, Subtext: asn})
	}
	return res
}

// GetTopThreatTypes returns the most frequent types of security threats.
func GetTopThreatTypes(ctx context.Context, limit int) []LabeledCount {
	if store == nil {
		return nil
	}
	query := store.dialect.Rebind("SELECT type, COUNT(*) as cnt FROM security_threats GROUP BY type ORDER BY cnt DESC LIMIT ?")
	rows, err := store.db.QueryContext(ctx, query, limit)
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

// GetThreatsByCountry returns the distribution of threats by country.
func GetThreatsByCountry(ctx context.Context, limit int) []LabeledCount {
	if store == nil {
		return nil
	}
	query := store.dialect.Rebind("SELECT country_code, COUNT(*) as cnt FROM security_threats WHERE country_code != '' GROUP BY country_code ORDER BY cnt DESC LIMIT ?")
	rows, err := store.db.QueryContext(ctx, query, limit)
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

// attackTrendBucketQuery builds the threat-count trend query, grouping by hour
// for short spans and by day for longer ones to keep the result set bounded.
func attackTrendBucketQuery(driver string, daily bool) string {
	isPostgres := driver == db.DriverPostgres || driver == "pgx"
	switch {
	case isPostgres && daily:
		return "SELECT TO_CHAR(timestamp, 'YYYY-MM-DD 00:00:00') as hr_bucket, COUNT(*) as cnt FROM security_threats WHERE timestamp >= ? GROUP BY hr_bucket ORDER BY hr_bucket ASC"
	case isPostgres:
		return "SELECT TO_CHAR(timestamp, 'YYYY-MM-DD HH24:00:00') as hr_bucket, COUNT(*) as cnt FROM security_threats WHERE timestamp >= ? GROUP BY hr_bucket ORDER BY hr_bucket ASC"
	case daily:
		return "SELECT strftime('%Y-%m-%d 00:00:00', timestamp) as hr_bucket, COUNT(*) as cnt FROM security_threats WHERE timestamp >= ? GROUP BY hr_bucket ORDER BY hr_bucket ASC"
	default:
		return "SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hr_bucket, COUNT(*) as cnt FROM security_threats WHERE timestamp >= ? GROUP BY hr_bucket ORDER BY hr_bucket ASC"
	}
}

// GetAttackTrend returns a time-series of security threat counts.
func GetAttackTrend(ctx context.Context, days int) []TrafficSample {
	if store == nil {
		return nil
	}
	if days <= 0 {
		days = 1
	}
	cutoff := time.Now().Add(time.Duration(-days*24) * time.Hour).Format(threatTimestampLayout)
	query := attackTrendBucketQuery(store.dialect.Driver, days > attackTrendDailyThresholdDays)

	rows, err := store.db.QueryContext(ctx, store.dialect.Rebind(query), cutoff)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var res []TrafficSample
	for rows.Next() {
		var bucket string
		var count uint64
		if err := rows.Scan(&bucket, &count); err != nil {
			logger.Default().LogError("attack trend: scan failed", "error", err)
			continue
		}
		// Handle potential varying length from different DB drivers
		if len(bucket) > 19 {
			bucket = bucket[:19]
		}
		t, err := time.Parse("2006-01-02 15:04:05", bucket)
		if err != nil {
			// try alternative format if Parse fails
			t, err = time.Parse("2006-01-02 15:04", bucket)
			if err != nil {
				logger.Default().LogError("attack trend: failed to parse bucket", "bucket", bucket, "error", err)
				continue
			}
		}
		res = append(res, TrafficSample{
			Timestamp: t.UnixMilli(),
			Requests:  count, // Reusing Requests field for threat count
		})
	}
	return res
}
