package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type AuditEntry struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Details   string    `json:"details"`
	Timestamp time.Time `json:"timestamp"`
	IPAddress string    `json:"ip_address"`
	Signature string    `json:"signature"`
}

type AuditManager struct {
	mu          sync.RWMutex
	config      *gateonv1.AuditConfig
	db          *sql.DB
	dialect     db.Dialect
	Broadcaster *Broadcaster
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
	})
	return err
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
	m.mu.RLock()
	cfg := m.config
	m.mu.RUnlock()

	if cfg != nil && !cfg.Enabled {
		return
	}

	entry := AuditEntry{
		ID:        uuid.NewString(),
		UserID:    userID,
		Action:    action,
		Resource:  resource,
		Details:   details,
		Timestamp: time.Now(),
		IPAddress: ip,
	}

	if cfg != nil && cfg.SignEntries && cfg.SignatureKey != "" {
		entry.Signature = m.sign(entry, cfg.SignatureKey)
	}

	query := m.dialect.Rebind("INSERT INTO audit_logs (id, user_id, action, resource, details, timestamp, ip_address, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
	_, err := m.db.ExecContext(ctx, query, entry.ID, entry.UserID, entry.Action, entry.Resource, entry.Details, entry.Timestamp, entry.IPAddress, entry.Signature)
	if err != nil {
		logger.L.LogError("audit: failed to write log", "error", err)
		return
	}
	if m.Broadcaster != nil {
		m.Broadcaster.Broadcast(entry)
	}
}

func (m *AuditManager) sign(entry AuditEntry, key string) string {
	payload := fmt.Sprintf("%s|%s|%s|%s|%s|%d|%s", entry.ID, entry.UserID, entry.Action, entry.Resource, entry.Details, entry.Timestamp.Unix(), entry.IPAddress)
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

func GetLogs(ctx context.Context, limit int) ([]AuditEntry, error) {
	if manager == nil {
		return nil, fmt.Errorf("audit manager not initialized")
	}
	query := manager.dialect.Rebind("SELECT id, user_id, action, resource, details, timestamp, ip_address, signature FROM audit_logs ORDER BY timestamp DESC LIMIT ?")
	rows, err := manager.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.UserID, &e.Action, &e.Resource, &e.Details, &e.Timestamp, &e.IPAddress, &e.Signature); err != nil {
			continue
		}
		logs = append(logs, e)
	}
	return logs, nil
}
