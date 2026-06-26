package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
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
	currentKey  string
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
	delete(b.subscribers, ch)
	close(ch)
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
		manager = &AuditManager{
			config:  cfg,
			db:      database,
			dialect: dialect,
			Broadcaster: &Broadcaster{
				subscribers: make(map[chan AuditEntry]struct{}),
			},
		}
		manager.loadLastHash()
	})
	return err
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
	m.mu.Lock()
	cfg := m.config
	lastHash := m.lastHash
	currentKey := m.currentKey
	m.mu.Unlock()

	if cfg != nil && !cfg.Enabled {
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
		PreviousHash: lastHash,
	}

	if cfg != nil && cfg.SignEntries && cfg.SignatureKey != "" {
		if currentKey == "" {
			currentKey = cfg.SignatureKey
		}
		entry.Signature = m.sign(entry, currentKey)

		// Rotate key for forward integrity
		nextKey := m.deriveNextKey(currentKey, entry.Signature)

		m.mu.Lock()
		m.lastHash = entry.Signature
		m.currentKey = nextKey
		m.mu.Unlock()
	}

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

func (m *AuditManager) deriveNextKey(currentKey, hash string) string {
	h := hmac.New(sha256.New, []byte(currentKey))
	h.Write([]byte(hash))
	return hex.EncodeToString(h.Sum(nil))
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
