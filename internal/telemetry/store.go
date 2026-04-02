package telemetry

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/logger"
)

// Persistent store for path metrics with retention control.
// Design goals:
// - Append/increment aggregated rows per (day, host, path)
// - Batch updates via a buffered channel to keep hot path non-blocking
// - Periodic pruning based on retention days
// Supports SQLite, PostgreSQL, MySQL, and MariaDB.

var (
	store     *pathStatsStore
	storeOnce sync.Once
)

type increment struct {
	host   string
	path   string
	latS   float64
	atTime time.Time
}

type traceRecord struct {
	ID            string
	OperationName string
	ServiceName   string
	DurationMs    float64
	Timestamp     time.Time
	Status        string
	Path          string
}

type pathStatsStore struct {
	db            *sql.DB
	dialect       db.Dialect
	inCh          chan increment
	traceInCh     chan traceRecord
	stopCh        chan struct{}
	stopped       atomic.Bool
	wg            sync.WaitGroup
	retentionDays atomic.Int32
}

// InitPathStatsStore initializes the database-backed store.
// databaseURL: sqlite:path, postgres://..., mysql://..., mariadb://...
// Plain path (e.g. "gateon.db") is treated as SQLite.
// It is safe to call multiple times; only the first call takes effect.
func InitPathStatsStore(databaseURL string, retentionDays int) error {
	var initErr error
	storeOnce.Do(func() {
		initErr = initStore(databaseURL, retentionDays)
	})
	return initErr
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

	st := &pathStatsStore{
		db:        database,
		dialect:   dialect,
		inCh:      make(chan increment, 4096),
		traceInCh: make(chan traceRecord, 4096),
		stopCh:    make(chan struct{}),
	}
	st.retentionDays.Store(int32(max(retentionDays, 1)))

	if err := db.Migrate(database, dialect); err != nil {
		_ = database.Close()
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	st.wg.Add(1)
	go st.loop()

	store = st
	return nil
}

func (s *pathStatsStore) upsertStmt(tx *sql.Tx) (*sql.Stmt, error) {
	if s.dialect.Driver == db.DriverMySQL {
		return tx.Prepare(QueryUpsertPathStatsMySQL)
	}
	q := s.dialect.Rebind(QueryUpsertPathStatsConflict)
	return tx.Prepare(q)
}

func (s *pathStatsStore) loop() {
	defer s.wg.Done()
	flushTicker := time.NewTicker(1 * time.Second)
	pruneTicker := time.NewTicker(1 * time.Hour)
	defer flushTicker.Stop()
	defer pruneTicker.Stop()

	batch := make([]increment, 0, 1024)
	traceBatch := make([]traceRecord, 0, 1024)

	flush := func() {
		if len(batch) > 0 {
			tx, err := s.db.Begin()
			if err != nil {
				logger.Default().Error().Err(err).Msg("path stats: begin transaction failed")
			} else {
				stmt, err := s.upsertStmt(tx)
				if err == nil {
					for _, inc := range batch {
						day := inc.atTime.UTC().Format("2006-01-02")
						if _, err := stmt.Exec(day, inc.host, inc.path, 1, inc.latS); err != nil {
							logger.Default().Error().Err(err).Msg("path stats: upsert failed")
						}
					}
					stmt.Close()
					_ = tx.Commit()
				} else {
					_ = tx.Rollback()
				}
			}
			batch = batch[:0]
		}

		if len(traceBatch) > 0 {
			tx, err := s.db.Begin()
			if err != nil {
				logger.Default().Error().Err(err).Msg("traces: begin transaction failed")
			} else {
				query := s.dialect.Rebind("INSERT INTO traces (id, operation_name, service_name, duration_ms, timestamp, status, path) VALUES (?, ?, ?, ?, ?, ?, ?)")
				stmt, err := tx.Prepare(query)
				if err == nil {
					for _, tr := range traceBatch {
						if _, err := stmt.Exec(tr.ID, tr.OperationName, tr.ServiceName, tr.DurationMs, tr.Timestamp, tr.Status, tr.Path); err != nil {
							logger.Default().Error().Err(err).Msg("traces: insert failed")
						}
					}
					stmt.Close()
					_ = tx.Commit()
				} else {
					_ = tx.Rollback()
				}
			}
			traceBatch = traceBatch[:0]
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
		case <-flushTicker.C:
			flush()
		case <-pruneTicker.C:
			s.prune()
		case <-s.stopCh:
			flush()
			return
		}
	}
}

func (s *pathStatsStore) prune() {
	days := int(s.retentionDays.Load())
	if days <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -days).UTC().Format("2006-01-02")
	q := s.dialect.Rebind(QueryPrunePathStats)
	if _, err := s.db.Exec(q, cutoff); err != nil {
		logger.Default().Error().Err(err).Msg("path stats: prune failed")
	}

	cutoffTime := time.Now().AddDate(0, 0, -days)
	qTraces := s.dialect.Rebind("DELETE FROM traces WHERE timestamp < ?")
	if _, err := s.db.Exec(qTraces, cutoffTime); err != nil {
		logger.Default().Error().Err(err).Msg("traces: prune failed")
	}
}

// ClosePathStatsStore stops background processing and closes the database.
func ClosePathStatsStore(ctx context.Context) error {
	if store == nil {
		return nil
	}
	if !store.stopped.Swap(true) {
		close(store.stopCh)
		c := make(chan struct{})
		go func() {
			store.wg.Wait()
			close(c)
		}()
		select {
		case <-c:
		case <-ctx.Done():
		}
		return store.db.Close()
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

// recordToStore attempts to enqueue an increment; if the store is not initialized or channel is full, it drops silently to avoid impacting the hot path.
func recordToStore(host, path string, latencySeconds float64, at time.Time) {
	if store == nil {
		return
	}
	select {
	case store.inCh <- increment{host: host, path: path, latS: latencySeconds, atTime: at}:
	default:
		// drop on backpressure to protect the request path
	}
}

// recordTraceToStore attempts to enqueue a trace record.
func recordTraceToStore(id, operationName, serviceName string, durationMs float64, timestamp time.Time, status, path string) {
	if store == nil {
		return
	}
	select {
	case store.traceInCh <- traceRecord{
		ID:            id,
		OperationName: operationName,
		ServiceName:   serviceName,
		DurationMs:    durationMs,
		Timestamp:     timestamp,
		Status:        status,
		Path:          path,
	}:
	default:
		// drop on backpressure
	}
}

// GetTraces returns the last N traces from the store.
func GetTraces(limit int) []traceRecord {
	if store == nil {
		return nil
	}
	if limit <= 0 {
		limit = 100
	}
	query := store.dialect.Rebind("SELECT id, operation_name, service_name, duration_ms, timestamp, status, path FROM traces ORDER BY timestamp DESC LIMIT ?")
	rows, err := store.db.Query(query, limit)
	if err != nil {
		logger.Default().Error().Err(err).Msg("traces: query failed")
		return nil
	}
	defer rows.Close()
	res := make([]traceRecord, 0, limit)
	for rows.Next() {
		var tr traceRecord
		if err := rows.Scan(&tr.ID, &tr.OperationName, &tr.ServiceName, &tr.DurationMs, &tr.Timestamp, &tr.Status, &tr.Path); err != nil {
			logger.Default().Error().Err(err).Msg("traces: scan failed")
			continue
		}
		res = append(res, tr)
	}
	return res
}

// GetPathStatsWindow returns aggregated stats from storage for the last `days` days.
// Falls back to in-memory stats on DB errors to ensure metrics are always available.
func GetPathStatsWindow(days int) []PathStats {
	if store == nil {
		return getInMemoryPathStats()
	}
	if days <= 0 {
		days = int(store.retentionDays.Load())
	}
	cutoff := time.Now().AddDate(0, 0, -days+1).UTC().Format("2006-01-02")
	q := store.dialect.Rebind(QueryGetPathStatsWin)
	rows, err := store.db.Query(q, cutoff)
	if err != nil {
		logger.Default().Error().Err(err).Msg("path stats: DB query failed, falling back to in-memory stats")
		return getInMemoryPathStats()
	}
	defer rows.Close()
	res := make([]PathStats, 0, 256)
	for rows.Next() {
		var host, p string
		var rc int64
		var lsum float64
		if err := rows.Scan(&host, &p, &rc, &lsum); err != nil {
			logger.Default().Error().Err(err).Msg("path stats: scan row failed")
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
			LatencySum:   lsum,
			AvgLatency:   float64(int(avg*1000+0.5)) / 1000.0,
		})
	}
	return res
}

// IsStoreEnabled returns true if the persistent store is active.
func IsStoreEnabled() bool {
	return store != nil
}

// CurrentRetentionDays returns the active retention configuration.
func CurrentRetentionDays() int {
	if store == nil {
		return 0
	}
	return int(store.retentionDays.Load())
}
