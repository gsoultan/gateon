package telemetry

// SQL queries for path stats. Dialect.Rebind replaces ? with $N (Postgres) as needed.
const (
	QueryUpsertPathStatsMySQL = `
	INSERT INTO path_stats (day, host, path, req_count, latency_sum_s, updated_at)
	VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	ON DUPLICATE KEY UPDATE
	  req_count = req_count + VALUES(req_count),
	  latency_sum_s = latency_sum_s + VALUES(latency_sum_s),
	  updated_at = CURRENT_TIMESTAMP;`

	QueryUpsertPathStatsConflict = `
	INSERT INTO path_stats (day, host, path, req_count, latency_sum_s, updated_at)
	VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	ON CONFLICT(day, host, path) DO UPDATE SET
	  req_count = req_count + excluded.req_count,
	  latency_sum_s = latency_sum_s + excluded.latency_sum_s,
	  updated_at = CURRENT_TIMESTAMP;`

	QueryPrunePathStats = "DELETE FROM path_stats WHERE day < ?"

	// SQLitePragmas enables WAL mode and NORMAL synchronous for SQLite (no-op for other drivers).
	SQLitePragmas        = "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;"
	QueryGetPathStatsWin = `SELECT host, path, SUM(req_count) AS rc, SUM(latency_sum_s) AS lsum
		FROM path_stats
		WHERE day >= ?
		GROUP BY host, path`

	QueryInsertTraceMySQL = `
	INSERT IGNORE INTO traces (id, operation_name, service_name, duration_ms, timestamp, status, path)
	VALUES (?, ?, ?, ?, ?, ?, ?);`

	QueryInsertTraceConflict = `
	INSERT INTO traces (id, operation_name, service_name, duration_ms, timestamp, status, path)
	VALUES (?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO NOTHING;`
)
