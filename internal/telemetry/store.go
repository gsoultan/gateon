package telemetry

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

// Persistent store for path metrics with retention control.
// Design goals:
// - Append/increment aggregated rows per (day, host, path)
// - Batch updates via a buffered channel to keep hot path non-blocking
// - Periodic pruning based on retention days

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
	inCh          chan increment
	stopCh        chan struct{}
	stopped       atomic.Bool
	wg            sync.WaitGroup
	retentionDays atomic.Int32
}

// InitPathStatsStore initializes the SQLite-backed store. It is safe to call multiple times; only the first call takes effect.
func InitPathStatsStore(dbPath string, retentionDays int) error {
	var initErr error
	storeOnce.Do(func() {
		initErr = initStore(dbPath, retentionDays)
	})
	return initErr
}

func initStore(dbPath string, retentionDays int) error {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return fmt.Errorf("ping sqlite: %w", err)
	}

	// Pragmas for durability vs performance tradeoff (safe defaults)
	_, _ = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;`)

	st := &pathStatsStore{
		db:     db,
		inCh:   make(chan increment, 4096),
		stopCh: make(chan struct{}),
	}
	st.retentionDays.Store(int32(max(retentionDays, 1)))

	if err := st.migrate(); err != nil {
		_ = db.Close()
		return err
	}

	st.wg.Add(1)
	go st.loop()

	store = st
	return nil
}

func (s *pathStatsStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS path_stats (
		  day TEXT NOT NULL,
		  host TEXT NOT NULL,
		  path TEXT NOT NULL,
		  req_count INTEGER NOT NULL DEFAULT 0,
		  latency_sum_s REAL NOT NULL DEFAULT 0,
		  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		  PRIMARY KEY(day, host, path)
		);
	`)
	return err
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
			batch = batch[:0]
			return
		}
		stmt, err := tx.Prepare(`
			INSERT INTO path_stats (day, host, path, req_count, latency_sum_s, updated_at)
			VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
			ON CONFLICT(day, host, path) DO UPDATE SET
			  req_count = req_count + excluded.req_count,
			  latency_sum_s = latency_sum_s + excluded.latency_sum_s,
			  updated_at = CURRENT_TIMESTAMP;
		`)
		if err != nil {
			_ = tx.Rollback()
			batch = batch[:0]
			return
		}
		for _, inc := range batch {
			day := inc.atTime.UTC().Format("2006-01-02")
			_, _ = stmt.Exec(day, inc.host, inc.path, 1, inc.latS)
		}
		_ = stmt.Close()
		_ = tx.Commit()
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
	_, _ = s.db.Exec(`DELETE FROM path_stats WHERE day < ?`, cutoff)
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
		// fallback to in-memory aggregation
		return GetPathStats()
	}
	if days <= 0 {
		days = int(store.retentionDays.Load())
	}
	cutoff := time.Now().AddDate(0, 0, -days+1).UTC().Format("2006-01-02")
	rows, err := store.db.Query(`
		SELECT host, path, SUM(req_count) AS rc, SUM(latency_sum_s) AS lsum
		FROM path_stats
		WHERE day >= ?
		GROUP BY host, path
	`, cutoff)
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
