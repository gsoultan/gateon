package audit

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type AuditEntry struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	Action       string    `json:"action"`
	Resource     string    `json:"resource"`
	Details      string    `json:"details"`
	Timestamp    time.Time `json:"timestamp"`
	IPAddress    string    `json:"ip_address"`
	Signature    string    `json:"signature"`
	PreviousHash string    `json:"previous_hash"`
}

type AuditManager struct {
	mu          sync.RWMutex
	config      *gateonv1.AuditConfig
	db          *sql.DB
	dialect     db.Dialect
	Broadcaster *Broadcaster
	lastHash    string
	stop        chan struct{}
}

// GenerateSignatureKey returns a cryptographically-random 256-bit key as a hex
// string, suitable for HMAC-SHA256 audit signing. Used when signing is enabled
// but no key was supplied.
func GenerateSignatureKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand should never fail; fall back to UUID-derived entropy.
		return strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", "")
	}
	return hex.EncodeToString(b)
}

type Broadcaster struct {
	mu          sync.RWMutex
	subscribers map[chan AuditEntry]struct{}
}

func (b *Broadcaster) Subscribe() chan AuditEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan AuditEntry, 10)
	b.subscribers[ch] = struct{}{}
	return ch
}

func (b *Broadcaster) Unsubscribe(ch chan AuditEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.subscribers[ch]; ok {
		delete(b.subscribers, ch)
		close(ch)
	}
}

func (b *Broadcaster) Broadcast(data AuditEntry) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.subscribers {
		select {
		case ch <- data:
		default:
		}
	}
}

var (
	manager *AuditManager
	once    sync.Once
)

func Init(cfg *gateonv1.AuditConfig, databaseURL string) error {
	var err error
	once.Do(func() {
		database, dialect, dberr := db.Open(databaseURL)
		if dberr != nil {
			err = dberr
			return
		}
		if migrateErr := db.Migrate(database, dialect); migrateErr != nil {
			err = migrateErr
			return
		}
		// Fallback: if signing is enabled but no key was provided, generate one so
		// entries are still signed. The API/registry layer is the primary place that
		// generates and persists this key; this covers boot paths with no API update.
		if cfg != nil && cfg.SignEntries && cfg.SignatureKey == "" {
			cfg.SignatureKey = GenerateSignatureKey()
		}
		manager = &AuditManager{
			config:  cfg,
			db:      database,
			dialect: dialect,
			Broadcaster: &Broadcaster{
				subscribers: make(map[chan AuditEntry]struct{}),
			},
			stop: make(chan struct{}),
		}
		manager.loadLastHash()
		go manager.runRetentionTask()
	})
	return err
}

func Stop() {
	if manager != nil {
		close(manager.stop)
	}
}

func (m *AuditManager) loadLastHash() {
	query := m.dialect.Rebind("SELECT signature FROM audit_logs ORDER BY timestamp DESC LIMIT 1")
	var lastHash string
	err := m.db.QueryRow(query).Scan(&lastHash)
	if err == nil {
		m.lastHash = lastHash
	}
}

func UpdateConfig(cfg *gateonv1.AuditConfig) {
	if manager == nil {
		return
	}
	if cfg != nil && cfg.SignEntries && cfg.SignatureKey == "" {
		cfg.SignatureKey = GenerateSignatureKey()
	}
	manager.mu.Lock()
	manager.config = cfg
	manager.mu.Unlock()
}

func Log(ctx context.Context, userID, action, resource, details, ip string) {
	if manager == nil {
		return
	}
	manager.log(ctx, userID, action, resource, details, ip)
}

func Subscribe() chan AuditEntry {
	if manager == nil || manager.Broadcaster == nil {
		return nil
	}
	return manager.Broadcaster.Subscribe()
}

func Unsubscribe(ch chan AuditEntry) {
	if manager == nil || manager.Broadcaster == nil {
		return
	}
	manager.Broadcaster.Unsubscribe(ch)
}

func (m *AuditManager) log(ctx context.Context, userID, action, resource, details, ip string) {
	// Hold the lock across read-lastHash → sign → update-lastHash so concurrent
	// writers chain off each other rather than forking the hash chain on a shared
	// previous_hash.
	m.mu.Lock()
	cfg := m.config

	if cfg != nil && !cfg.Enabled {
		m.mu.Unlock()
		return
	}

	entry := AuditEntry{
		ID:           uuid.NewString(),
		UserID:       userID,
		Action:       action,
		Resource:     resource,
		Details:      details,
		Timestamp:    time.Now(),
		IPAddress:    ip,
		PreviousHash: m.lastHash,
	}

	// Sign with the STATIC configured key (not a per-entry rotated key) and chain
	// via previous_hash. A fixed key is what makes the chain independently
	// verifiable after a restart: a verifier holding the configured key can
	// recompute every signature in order and detect any insertion, edit or
	// reorder. (The previous forward-ratchet key rotation was unverifiable because
	// the rotated key was in-memory only and lost on restart.)
	if cfg != nil && cfg.SignEntries && cfg.SignatureKey != "" {
		entry.Signature = m.sign(entry, cfg.SignatureKey)
		m.lastHash = entry.Signature
	}
	m.mu.Unlock()

	query := m.dialect.Rebind("INSERT INTO audit_logs (id, user_id, action, resource, details, timestamp, ip_address, signature, previous_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
	_, err := m.db.ExecContext(ctx, query, entry.ID, entry.UserID, entry.Action, entry.Resource, entry.Details, entry.Timestamp, entry.IPAddress, entry.Signature, entry.PreviousHash)
	if err != nil {
		logger.L.LogError("audit: failed to write log", "error", err)
		return
	}
	// Broadcast to real-time subscribers (for Command Center etc)
	if m.Broadcaster != nil {
		m.Broadcaster.Broadcast(entry)
	}
}

func (m *AuditManager) sign(entry AuditEntry, key string) string {
	payload := fmt.Sprintf("%s|%s|%s|%s|%s|%d|%s|%s", entry.ID, entry.UserID, entry.Action, entry.Resource, entry.Details, entry.Timestamp.Unix(), entry.IPAddress, entry.PreviousHash)
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

func GetLogs(ctx context.Context, limit int) ([]AuditEntry, error) {
	if manager == nil {
		return nil, fmt.Errorf("audit manager not initialized")
	}
	query := manager.dialect.Rebind("SELECT id, user_id, action, resource, details, timestamp, ip_address, signature, previous_hash FROM audit_logs ORDER BY timestamp DESC LIMIT ?")
	rows, err := manager.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.UserID, &e.Action, &e.Resource, &e.Details, &e.Timestamp, &e.IPAddress, &e.Signature, &e.PreviousHash); err != nil {
			continue
		}
		logs = append(logs, e)
	}
	return logs, nil
}

// GetLogsPaginated returns a page of audit logs (newest first) along with the
// total number of rows matching the optional case-insensitive search across
// action, resource, user_id and details. page is 0-indexed.
func (m *AuditManager) runRetentionTask() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	// Run once at start
	m.checkRetention()

	for {
		select {
		case <-ticker.C:
			m.checkRetention()
		case <-m.stop:
			return
		}
	}
}

func (m *AuditManager) checkRetention() {
	m.mu.RLock()
	retentionDays := m.config.RetentionDays
	archiveOnRetention := m.config.ArchiveOnRetention
	m.mu.RUnlock()

	if retentionDays <= 0 {
		return
	}

	cutoff := time.Now().AddDate(0, 0, -int(retentionDays))

	if archiveOnRetention {
		if err := m.archiveLogs(cutoff); err != nil {
			logger.L.LogError("audit: failed to archive logs", "error", err)
			// Continue to deletion anyway? Maybe safer not to if archive failed.
			return
		}
	}

	query := m.dialect.Rebind("DELETE FROM audit_logs WHERE timestamp < ?")
	result, err := m.db.Exec(query, cutoff)
	if err != nil {
		logger.L.LogError("audit: failed to delete old logs", "error", err)
	} else {
		rows, _ := result.RowsAffected()
		if rows > 0 {
			logger.L.LogInfo("audit: retention task completed", "deleted_rows", rows)
		}
	}
}

func (m *AuditManager) archiveLogs(cutoff time.Time) error {
	// Query logs to archive
	query := m.dialect.Rebind("SELECT id, user_id, action, resource, details, timestamp, ip_address, signature, previous_hash FROM audit_logs WHERE timestamp < ? ORDER BY timestamp ASC")
	rows, err := m.db.Query(query, cutoff)
	if err != nil {
		return err
	}
	defer rows.Close()

	var logs []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.UserID, &e.Action, &e.Resource, &e.Details, &e.Timestamp, &e.IPAddress, &e.Signature, &e.PreviousHash); err != nil {
			continue
		}
		logs = append(logs, e)
	}

	if len(logs) == 0 {
		return nil
	}

	// Create archive directory
	archiveDir := filepath.Join(config.DataDir(), "audit", "archives")
	if err := os.MkdirAll(archiveDir, 0o750); err != nil {
		return err
	}

	// Filename: audit_archive_2024-01-01_to_2024-02-01.json.br
	first := logs[0].Timestamp.Format("2006-01-02")
	last := logs[len(logs)-1].Timestamp.Format("2006-01-02")
	filename := fmt.Sprintf("audit_archive_%s_to_%s_%s.json.br", first, last, uuid.NewString()[:8])
	path := filepath.Join(archiveDir, filename)

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Use Brotli for best smallest algorithm as requested
	bw := brotli.NewWriterLevel(f, brotli.BestCompression)
	defer bw.Close()

	enc := json.NewEncoder(bw)
	if err := enc.Encode(logs); err != nil {
		return err
	}

	logger.L.LogInfo("audit: logs archived", "filename", filename, "count", len(logs))
	return nil
}

func ListArchives() ([]*gateonv1.AuditArchive, error) {
	archiveDir := filepath.Join(config.DataDir(), "audit", "archives")
	entries, err := os.ReadDir(archiveDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*gateonv1.AuditArchive{}, nil
		}
		return nil, err
	}

	var archives []*gateonv1.AuditArchive
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json.br") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		archives = append(archives, &gateonv1.AuditArchive{
			Filename:  entry.Name(),
			Size:      info.Size(),
			CreatedAt: info.ModTime().Format(time.RFC3339),
		})
	}
	// Sort by newest first
	slices.SortFunc(archives, func(a, b *gateonv1.AuditArchive) int {
		return strings.Compare(b.CreatedAt, a.CreatedAt)
	})
	return archives, nil
}

func GetArchive(filename string) ([]byte, error) {
	// Sanitize filename
	filename = filepath.Base(filename)
	path := filepath.Join(config.DataDir(), "audit", "archives", filename)

	// Open and read (we return raw bytes, decompression is handled by UI or we could decompress here)
	// The user said "open it through gateon ui", usually UI can handle decompression if it's small,
	// but Brotli in JS might be heavy. Let's decompress here to make it easier for UI to display.
	// Actually, "open it through gateon ui" might mean download or view.
	// If it's a JSON archive, viewing it in UI is better.

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	br := brotli.NewReader(f)
	return io.ReadAll(br)
}

func GetLogsPaginated(ctx context.Context, page, pageSize int, search string) ([]AuditEntry, int, error) {
	if manager == nil {
		return nil, 0, fmt.Errorf("audit manager not initialized")
	}
	if pageSize <= 0 {
		pageSize = 50
	}
	if page < 0 {
		page = 0
	}

	where := ""
	var args []any
	if search = strings.TrimSpace(search); search != "" {
		where = " WHERE LOWER(action) LIKE ? OR LOWER(resource) LIKE ? OR LOWER(user_id) LIKE ? OR LOWER(details) LIKE ?"
		like := "%" + strings.ToLower(search) + "%"
		args = append(args, like, like, like, like)
	}

	var total int
	countQuery := manager.dialect.Rebind("SELECT COUNT(*) FROM audit_logs" + where)
	if err := manager.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if total == 0 {
		return []AuditEntry{}, 0, nil
	}

	offset := page * pageSize
	pageArgs := append(append([]any{}, args...), pageSize, offset)
	query := manager.dialect.Rebind("SELECT id, user_id, action, resource, details, timestamp, ip_address, signature, previous_hash FROM audit_logs" + where + " ORDER BY timestamp DESC LIMIT ? OFFSET ?")
	rows, err := manager.db.QueryContext(ctx, query, pageArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	logs := make([]AuditEntry, 0, pageSize)
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.UserID, &e.Action, &e.Resource, &e.Details, &e.Timestamp, &e.IPAddress, &e.Signature, &e.PreviousHash); err != nil {
			continue
		}
		logs = append(logs, e)
	}
	return logs, total, nil
}
