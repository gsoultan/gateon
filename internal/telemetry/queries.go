package telemetry

// SQL queries for path stats. Dialect.Rebind replaces ? with $N (Postgres) as needed.
const (
	QueryUpsertPathStatsMySQL = `
	INSERT INTO path_stats (day, host, path, req_count, latency_sum_s, bytes_total, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	ON DUPLICATE KEY UPDATE
	  req_count = req_count + VALUES(req_count),
	  latency_sum_s = latency_sum_s + VALUES(latency_sum_s),
	  bytes_total = bytes_total + VALUES(bytes_total),
	  updated_at = CURRENT_TIMESTAMP;`

	QueryUpsertPathStatsConflict = `
	INSERT INTO path_stats (day, host, path, req_count, latency_sum_s, bytes_total, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	ON CONFLICT(day, host, path) DO UPDATE SET
	  req_count = req_count + excluded.req_count,
	  latency_sum_s = latency_sum_s + excluded.latency_sum_s,
	  bytes_total = bytes_total + excluded.bytes_total,
	  updated_at = CURRENT_TIMESTAMP;`

	QueryPrunePathStats = "DELETE FROM path_stats WHERE day < ?"

	// SQLitePragmas enables WAL mode and NORMAL synchronous for SQLite (no-op for other drivers).
	SQLitePragmas        = "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;"
	QueryGetPathStatsWin = `SELECT host, path, SUM(req_count) AS rc, SUM(latency_sum_s) AS lsum, SUM(bytes_total) AS bsum
		FROM path_stats
		WHERE day >= ?
		GROUP BY host, path`

	QueryUpsertDomainStatsMySQL = `
	INSERT INTO domain_stats (day, hour, domain, req_count, latency_sum_s, bytes_total, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	ON DUPLICATE KEY UPDATE
	  req_count = req_count + VALUES(req_count),
	  latency_sum_s = latency_sum_s + VALUES(latency_sum_s),
	  bytes_total = bytes_total + VALUES(bytes_total),
	  updated_at = CURRENT_TIMESTAMP;`

	QueryUpsertDomainStatsConflict = `
	INSERT INTO domain_stats (day, hour, domain, req_count, latency_sum_s, bytes_total, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	ON CONFLICT(day, hour, domain) DO UPDATE SET
	  req_count = req_count + excluded.req_count,
	  latency_sum_s = latency_sum_s + excluded.latency_sum_s,
	  bytes_total = bytes_total + excluded.bytes_total,
	  updated_at = CURRENT_TIMESTAMP;`

	QueryPruneDomainStats = "DELETE FROM domain_stats WHERE day < ?"

	QueryGetDomainStatsWin = `SELECT domain, SUM(req_count) AS rc, SUM(latency_sum_s) AS lsum, SUM(bytes_total) AS bsum
		FROM domain_stats
		WHERE day >= ?
		GROUP BY domain`

	QueryGetDomainStatsHourly = `SELECT domain, hour, req_count, latency_sum_s, bytes_total
		FROM domain_stats
		WHERE day = ? AND hour = ?`

	QueryInsertTraceMySQL = `
	INSERT IGNORE INTO traces (id, operation_name, service_name, duration_ms, timestamp, status, path, source_ip)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?);`

	QueryInsertTraceConflict = `
	INSERT INTO traces (id, operation_name, service_name, duration_ms, timestamp, status, path, source_ip)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO NOTHING;`
)
