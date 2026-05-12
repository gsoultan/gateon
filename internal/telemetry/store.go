package telemetry

import (
	"cmp"
	"context"
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/audit"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/logger"
	lru "github.com/hashicorp/golang-lru"
)

// AlertingHandler is a function type for alerting integration.
type AlertingHandler func(*SecurityThreat)

var (
	onThreatAlert AlertingHandler
	alertMu       sync.RWMutex
)

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
	ID              string
	OperationName   string
	ServiceName     string
	DurationMs      float64
	Timestamp       time.Time
	Status          string
	Path            string
	SourceIP        string
	Fingerprint     string
	CountryCode     string
	UserAgent       string
	Method          string
	Referer         string
	RequestURI      string
	JA3             string
	RequestHeaders  string
	RequestBody     string
	ResponseHeaders string
	ResponseBody    string
	JA4             string
}

type SecurityThreat struct {
	ID          string
	Type        string
	SourceIP    string
	Fingerprint string
	Score       float64
	Details     string
	Time        time.Time
	JA3         string
	JA4         string
	RouteID     string
	RequestURI  string
	Category    string
	Severity    string
	ASN         string
	ActionTaken string
	CountryCode string
}

type pathStatsStore struct {
	db                          *sql.DB
	dialect                     db.Dialect
	inCh                        chan increment
	traceInCh                   chan TraceRecord
	threatInCh                  chan SecurityThreat
	stopCh                      chan struct{}
	stopped                     atomic.Bool
	wg                          sync.WaitGroup
	retentionDays               atomic.Int32
	pathStatsRetentionDays      atomic.Int32
	accessLogRetentionDays      atomic.Int32
	securityThreatRetentionDays atomic.Int32
	auditLogRetentionDays       atomic.Int32
	pruning                     atomic.Bool
	scoreCache                  *lru.ARCCache
	unmitigatedCache            *lru.ARCCache
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

	st := &pathStatsStore{
		db:         database,
		dialect:    dialect,
		inCh:       make(chan increment, 4096),
		traceInCh:  make(chan TraceRecord, 4096),
		threatInCh: make(chan SecurityThreat, 1024),
		stopCh:     make(chan struct{}),
	}
	st.retentionDays.Store(int32(max(retentionDays, 1)))

	if cache, err := lru.NewARC(10000); err == nil {
		st.scoreCache = cache
	}
	if cache, err := lru.NewARC(1000); err == nil {
		st.unmitigatedCache = cache
	}

	if err := db.Migrate(database, dialect); err != nil {
		_ = database.Close()
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	st.wg.Go(st.loop)

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

func (s *pathStatsStore) domainUpsertStmt(tx *sql.Tx) (*sql.Stmt, error) {
	if s.dialect.Driver == db.DriverMySQL {
		return tx.Prepare(QueryUpsertDomainStatsMySQL)
	}
	q := s.dialect.Rebind(QueryUpsertDomainStatsConflict)
	return tx.Prepare(q)
}

func (s *pathStatsStore) traceInsertStmt(tx *sql.Tx) (*sql.Stmt, error) {
	if s.dialect.Driver == db.DriverMySQL {
		return tx.Prepare(QueryInsertTraceMySQL)
	}
	q := s.dialect.Rebind(QueryInsertTraceConflict)
	return tx.Prepare(q)
}

func (s *pathStatsStore) threatInsertStmt(tx *sql.Tx) (*sql.Stmt, error) {
	q := s.dialect.Rebind("INSERT INTO security_threats (id, type, source_ip, fingerprint, score, details, timestamp, ja3, ja4, route_id, request_uri, category, severity, asn, action_taken, country_code) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
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
			tx, err := s.db.Begin()
			if err != nil {
				logger.Default().LogError("traces: begin transaction failed", "error", err)
			} else {
				if stmt, err := s.traceInsertStmt(tx); err == nil {
					for _, tr := range traceBatch {
						if _, err := stmt.Exec(tr.ID, tr.OperationName, tr.ServiceName, tr.DurationMs, tr.Timestamp, tr.Status, tr.Path, tr.SourceIP, tr.Fingerprint, tr.CountryCode, tr.UserAgent, tr.Method, tr.Referer, tr.RequestURI, tr.JA3, tr.RequestHeaders, tr.RequestBody, tr.ResponseHeaders, tr.ResponseBody, tr.JA4); err != nil {
							logger.Default().LogError("traces: insert failed", "error", err)
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

		if len(threatBatch) > 0 {
			tx, err := s.db.Begin()
			if err != nil {
				logger.Default().LogError("threats: begin transaction failed", "error", err)
			} else {
				if stmt, err := s.threatInsertStmt(tx); err == nil {
					for _, th := range threatBatch {
						if _, err := stmt.Exec(th.ID, th.Type, th.SourceIP, th.Fingerprint, th.Score, th.Details, th.Time, th.JA3, th.JA4, th.RouteID, th.RequestURI, th.Category, th.Severity, th.ASN, th.ActionTaken, th.CountryCode); err != nil {
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

	// 1. Path Stats & Domain Stats Retention
	days := int(s.pathStatsRetentionDays.Load())
	if days <= 0 {
		days = int(s.retentionDays.Load())
	}
	if days > 0 {
		cutoff := time.Now().AddDate(0, 0, -days).UTC().Format("2006-01-02")
		q := s.dialect.Rebind(QueryPrunePathStats)
		if _, err := s.db.ExecContext(ctx, q, cutoff); err != nil {
			logger.Default().LogError("path stats: prune failed", "error", err)
		}

		qDomain := s.dialect.Rebind(QueryPruneDomainStats)
		if _, err := s.db.ExecContext(ctx, qDomain, cutoff); err != nil {
			logger.Default().LogError("domain stats: prune failed", "error", err)
		}
	}

	// 2. Access Logs (Traces) Retention
	accessDays := int(s.accessLogRetentionDays.Load())
	if accessDays <= 0 {
		accessDays = int(s.retentionDays.Load())
	}
	if accessDays > 0 {
		cutoffTime := time.Now().AddDate(0, 0, -accessDays)
		qTraces := s.dialect.Rebind("DELETE FROM traces WHERE timestamp < ?")
		if _, err := s.db.ExecContext(ctx, qTraces, cutoffTime); err != nil {
			logger.Default().LogError("traces: prune failed", "error", err)
		}
	}

	// 3. Security Threats Retention
	threatDays := int(s.securityThreatRetentionDays.Load())
	if threatDays <= 0 {
		threatDays = int(s.retentionDays.Load())
	}
	if threatDays > 0 {
		cutoffTime := time.Now().AddDate(0, 0, -threatDays)
		qThreats := s.dialect.Rebind("DELETE FROM security_threats WHERE timestamp < ?")
		if _, err := s.db.ExecContext(ctx, qThreats, cutoffTime); err != nil {
			logger.Default().LogError("security_threats: prune failed", "error", err)
		}
	}

	// 4. Audit Logs (if any table exists)
	auditDays := int(s.auditLogRetentionDays.Load())
	if auditDays > 0 {
		// Assuming an audit_logs table exists or will be added
		cutoffTime := time.Now().AddDate(0, 0, -auditDays)
		qAudit := s.dialect.Rebind("DELETE FROM audit_logs WHERE timestamp < ?")
		_, _ = s.db.ExecContext(ctx, qAudit, cutoffTime)
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
	default:
		// drop on backpressure
	}
}

// recordTraceToStore attempts to enqueue a trace record.
func recordTraceToStore(id, operationName, serviceName string, durationMs float64, timestamp time.Time, status, path, sourceIP, fingerprint, countryCode, userAgent, method, referer, requestURI, ja3, ja4, reqHeaders, reqBody, respHeaders, respBody string) {
	if store == nil {
		return
	}
	select {
	case store.traceInCh <- TraceRecord{
		ID:              id,
		OperationName:   operationName,
		ServiceName:     serviceName,
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

	if t.CountryCode == "" && t.SourceIP != "" {
		t.CountryCode = ResolveCountry(t.SourceIP)
	}

	if store.scoreCache != nil {
		current, ok := store.scoreCache.Get(t.SourceIP)
		score := t.Score
		if ok {
			score += current.(float64)
		}
		store.scoreCache.Add(t.SourceIP, score)
	}

	if t.Fingerprint != "" {
		DecreaseReputation(t.Fingerprint, t.Score/2, t.Type) // Penalty is half the threat score
	}

	// Increment Prometheus counter
	MitigatedThreatsTotal.WithLabelValues(cmp.Or(t.Category, "general"), cmp.Or(t.Severity, "medium"), cmp.Or(t.ActionTaken, "blocked")).Inc()

	alertMu.RLock()
	h := onThreatAlert
	alertMu.RUnlock()
	if h != nil {
		h(&t)
	}

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
	if store == nil {
		return nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	query := store.dialect.Rebind("SELECT id, operation_name, service_name, duration_ms, timestamp, status, path, source_ip, country_code, user_agent, method, referer, request_uri, ja3, ja4, request_headers, request_body, response_headers, response_body FROM traces ORDER BY timestamp DESC LIMIT ?")
	rows, err := store.db.QueryContext(ctx, query, limit)
	if err != nil {
		logger.Default().LogError("traces: query failed", "error", err)
		return nil
	}
	defer rows.Close()
	res := make([]TraceRecord, 0, min(limit, 100))
	for rows.Next() {
		var tr TraceRecord
		var reqHeaders, reqBody, respHeaders, respBody sql.NullString
		if err := rows.Scan(&tr.ID, &tr.OperationName, &tr.ServiceName, &tr.DurationMs, &tr.Timestamp, &tr.Status, &tr.Path, &tr.SourceIP, &tr.CountryCode, &tr.UserAgent, &tr.Method, &tr.Referer, &tr.RequestURI, &tr.JA3, &tr.JA4, &reqHeaders, &reqBody, &respHeaders, &respBody); err != nil {
			logger.Default().LogError("traces: scan failed", "error", err)
			continue
		}
		tr.RequestHeaders = reqHeaders.String
		tr.RequestBody = reqBody.String
		tr.ResponseHeaders = respHeaders.String
		tr.ResponseBody = respBody.String
		res = append(res, tr)
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
	day := time.Now().UTC().Format("2006-01-02")
	q := store.dialect.Rebind(QueryGetTotalTrafficToday)
	var rc, bsum sql.NullInt64
	err := store.db.QueryRowContext(ctx, q, day).Scan(&rc, &bsum)
	if err != nil {
		return 0, 0
	}
	return uint64(rc.Int64), uint64(bsum.Int64)
}

// GetSystemTrafficHistory returns traffic samples for the last N days.
func GetSystemTrafficHistory(ctx context.Context, days int) []TrafficSample {
	if store == nil {
		return nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02")
	q := store.dialect.Rebind(QueryGetTrafficHistory)
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

		// Convert day and bucket back to timestamp
		t, _ := time.Parse("2006-01-02", day)
		// bucket is half-hour index (0-47)
		t = t.Add(time.Duration(bucket*30) * time.Minute)

		samples = append(samples, TrafficSample{
			Timestamp: t.UnixMilli(),
			Requests:  uint64(rc),
			Bytes:     uint64(bsum),
		})
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

// IsStoreEnabled returns true if the persistent store is active.
// GetSecurityThreats returns the last N security threats from the store.
func GetSecurityThreats(ctx context.Context, limit int) []SecurityThreat {
	if store == nil {
		return nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	query := store.dialect.Rebind("SELECT id, type, source_ip, fingerprint, score, details, timestamp, ja3, ja4, route_id, request_uri, category, severity, asn, action_taken, country_code FROM security_threats ORDER BY timestamp DESC LIMIT ?")
	rows, err := store.db.QueryContext(ctx, query, limit)
	if err != nil {
		logger.Default().LogError("threats: query failed", "error", err)
		return nil
	}
	defer rows.Close()
	res := make([]SecurityThreat, 0, min(limit, 100))
	for rows.Next() {
		var th SecurityThreat
		if err := rows.Scan(&th.ID, &th.Type, &th.SourceIP, &th.Fingerprint, &th.Score, &th.Details, &th.Time, &th.JA3, &th.JA4, &th.RouteID, &th.RequestURI, &th.Category, &th.Severity, &th.ASN, &th.ActionTaken, &th.CountryCode); err != nil {
			logger.Default().LogError("threats: scan failed", "error", err)
			continue
		}
		res = append(res, th)
	}
	return res
}

func IsStoreEnabled() bool {
	return store != nil
}

// PingStore checks the health of the telemetry database.
func PingStore() error {
	if store == nil {
		return fmt.Errorf("telemetry store not initialized")
	}
	return store.db.Ping()
}

// CurrentRetentionDays returns the active retention configuration.
func CurrentRetentionDays() int {
	if store == nil {
		return 0
	}
	return int(store.retentionDays.Load())
}

// GetTopThreatSources returns the most frequent attacking IP addresses.
func GetTopThreatSources(ctx context.Context, limit int) []LabeledCount {
	if store == nil {
		return nil
	}
	query := store.dialect.Rebind("SELECT source_ip, COUNT(*) as cnt FROM security_threats GROUP BY source_ip ORDER BY cnt DESC LIMIT ?")
	rows, err := store.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var res []LabeledCount
	for rows.Next() {
		var label string
		var count float64
		if err := rows.Scan(&label, &count); err == nil {
			res = append(res, LabeledCount{Label: label, Value: count})
		}
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
		if err := rows.Scan(&label, &count); err == nil {
			res = append(res, LabeledCount{Label: label, Value: count})
		}
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
		if err := rows.Scan(&label, &count); err == nil {
			res = append(res, LabeledCount{Label: label, Value: count})
		}
	}
	return res
}

// GetAttackTrend returns a time-series of security threat counts.
func GetAttackTrend(ctx context.Context, days int) []TrafficSample {
	if store == nil {
		return nil
	}
	if days <= 0 {
		days = 1
	}
	cutoff := time.Now().AddDate(0, 0, -days).Format("2006-01-02")
	// Group by day and hour for trend
	var query string
	if store.dialect.Driver == db.DriverPostgres || store.dialect.Driver == "pgx" {
		query = "SELECT TO_CHAR(timestamp, 'YYYY-MM-DD') as day, EXTRACT(HOUR FROM timestamp) as hr, COUNT(*) as cnt FROM security_threats WHERE timestamp >= ? GROUP BY day, hr ORDER BY day ASC, hr ASC"
	} else {
		query = "SELECT strftime('%Y-%m-%d', timestamp) as day, (strftime('%H', timestamp)) as hr, COUNT(*) as cnt FROM security_threats WHERE timestamp >= ? GROUP BY day, hr ORDER BY day ASC, hr ASC"
	}

	rows, err := store.db.QueryContext(ctx, store.dialect.Rebind(query), cutoff)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var res []TrafficSample
	for rows.Next() {
		var day string
		var hr int
		var count uint64
		if err := rows.Scan(&day, &hr, &count); err == nil {
			t, _ := time.Parse("2006-01-02", day)
			t = t.Add(time.Duration(hr) * time.Hour)
			res = append(res, TrafficSample{
				Timestamp: t.UnixMilli(),
				Requests:  count, // Reusing Requests field for threat count
			})
		}
	}
	return res
}
