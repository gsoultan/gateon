package telemetry

// threatTimestampLayout is the datetime layout used to compare against the
// security_threats.timestamp column, which is persisted from a time.Time.
const threatTimestampLayout = "2006-01-02 15:04:05"

// Aggregation thresholds keep query result sets small (bounded memory, storage
// and bandwidth) when long spans are requested.
const (
	// trafficDailyAggregationThresholdDays switches traffic history from
	// half-hour buckets to a single bucket per day for longer spans.
	trafficDailyAggregationThresholdDays = 31
	// attackTrendDailyThresholdDays switches the attack trend from hourly to
	// daily buckets for longer spans.
	attackTrendDailyThresholdDays = 7
)

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
	// auto_vacuum=INCREMENTAL lets prune() reclaim freed pages via PRAGMA
	// incremental_vacuum instead of growing the DB file unbounded.
	SQLitePragmas        = "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA auto_vacuum=INCREMENTAL;"
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

	QueryGetTotalTrafficToday = `SELECT SUM(req_count), SUM(bytes_total)
		FROM domain_stats
		WHERE day = ?`

	QueryGetActiveThreatsToday = `SELECT COUNT(*) FROM security_threats
		WHERE timestamp >= ? AND action_taken NOT IN ('blocked', 'challenged', 'shunned')`

	QueryGetMitigatedThreatsToday = `SELECT COUNT(*) FROM security_threats
		WHERE timestamp >= ? AND action_taken IN ('blocked', 'challenged', 'shunned')`

	QueryGetTotalTrafficRolling24h = `SELECT COALESCE(SUM(req_count), 0), COALESCE(SUM(bytes_total), 0)
		FROM domain_stats
		WHERE (day = ? AND hour <= ?) OR (day = ? AND hour > ?)`

	QueryGetDomainStatsRolling24h = `SELECT domain, COALESCE(SUM(req_count), 0) AS rc, COALESCE(SUM(latency_sum_s), 0) AS lsum, COALESCE(SUM(bytes_total), 0) AS bsum
		FROM domain_stats
		WHERE (day = ? AND hour <= ?) OR (day = ? AND hour > ?)
		GROUP BY domain`

	QueryGetActiveThreatsRolling24h = `SELECT COUNT(*) FROM security_threats
		WHERE timestamp >= ? AND action_taken NOT IN ('blocked', 'challenged', 'shunned')`

	QueryGetMitigatedThreatsRolling24h = `SELECT COUNT(*) FROM security_threats
		WHERE timestamp >= ? AND action_taken IN ('blocked', 'challenged', 'shunned')`

	// QueryGetWAFBlockCounts returns the number of persisted WAF block events
	// grouped by route. It is used at startup to restore the in-memory
	// gateon_middleware_waf_blocked_total counter so the dashboard does not
	// reset to 0 on every restart. The result set is tiny (one row per route).
	QueryGetWAFBlockCounts = `SELECT COALESCE(route_id, ''), COUNT(*) FROM security_threats
		WHERE type = 'waf_block'
		GROUP BY route_id`

	QueryGetTrafficHistory = `SELECT day, hour, SUM(req_count), SUM(bytes_total)
		FROM domain_stats
		WHERE day >= ?
		GROUP BY day, hour
		ORDER BY day ASC, hour ASC`

	// QueryGetTrafficHistoryDaily collapses each day into a single bucket. It is
	// used for long spans (month/year) so the snapshot stays small in memory and
	// over the wire instead of returning up to 48 half-hour rows per day.
	QueryGetTrafficHistoryDaily = `SELECT day, 0 AS bucket, SUM(req_count), SUM(bytes_total)
		FROM domain_stats
		WHERE day >= ?
		GROUP BY day
		ORDER BY day ASC`

	QueryGetDomainStatsHourly = `SELECT domain, hour, req_count, latency_sum_s, bytes_total
		FROM domain_stats
		WHERE day = ? AND hour = ?`

	QueryInsertTraceMySQL = `
	INSERT IGNORE INTO traces (id, operation_name, service_name, duration_ms, timestamp, status, path, source_ip, fingerprint, country_code, user_agent, method, referer, request_uri, ja3, ja4, request_headers, request_body, response_headers, response_body)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`

	QueryInsertTraceConflict = `
	INSERT INTO traces (id, operation_name, service_name, duration_ms, timestamp, status, path, source_ip, fingerprint, country_code, user_agent, method, referer, request_uri, ja3, ja4, request_headers, request_body, response_headers, response_body)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO NOTHING;`
)
