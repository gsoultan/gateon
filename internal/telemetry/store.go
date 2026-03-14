package telemetry

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gateon/gateon/internal/db"
	"github.com/gateon/gateon/internal/logger"
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

type pathStatsStore struct {
	db            *sql.DB
	dialect       db.Dialect
	inCh          chan increment
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
		db:      database,
		dialect: dialect,
		inCh:    make(chan increment, 4096),
		stopCh:  make(chan struct{}),
	}
	st.retentionDays.Store(int32(max(retentionDays, 1)))

	if err := st.migrate(); err != nil {
		_ = database.Close()
		return err
	}

	st.wg.Add(1)
	go st.loop()

	store = st
	return nil
}

func (s *pathStatsStore) migrate() error {
	query := QueryCreatePathStatsDefault
	if s.dialect.Driver == db.DriverSQLite {
		query = QueryCreatePathStatsSQLite
	}
	_, err := s.db.Exec(query)
	return err
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
	flush := func() {
		if len(batch) == 0 {
			return
		}
		tx, err := s.db.Begin()
		if err != nil {
			logger.Default().Error().Err(err).Msg("path stats: begin transaction failed")
			batch = batch[:0]
			return
		}
		defer func() {
			_ = tx.Rollback()
		}()
		stmt, err := s.upsertStmt(tx)
		if err != nil {
			batch = batch[:0]
			return
		}
		defer stmt.Close()
		for _, inc := range batch {
			day := inc.atTime.UTC().Format("2006-01-02")
			if _, err := stmt.Exec(day, inc.host, inc.path, 1, inc.latS); err != nil {
				logger.Default().Error().Err(err).Msg("path stats: upsert failed")
				batch = batch[:0]
				return
			}
		}
		if err := tx.Commit(); err != nil {
			logger.Default().Error().Err(err).Msg("path stats: commit failed")
		}
		batch = batch[:0]
	}

	for {
		select {
		case inc := <-s.inCh:
			batch = append(batch, inc)
			if len(batch) >= cap(batch) {
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

// GetPathStatsWindow returns aggregated stats from storage for the last `days` days.
func GetPathStatsWindow(days int) []PathStats {
	if store == nil {
		return GetPathStats()
	}
	if days <= 0 {
		days = int(store.retentionDays.Load())
	}
	cutoff := time.Now().AddDate(0, 0, -days+1).UTC().Format("2006-01-02")
	q := store.dialect.Rebind(QueryGetPathStatsWin)
	rows, err := store.db.Query(q, cutoff)
	if err != nil {
		return nil
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
