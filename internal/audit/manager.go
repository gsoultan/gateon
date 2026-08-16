// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

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
	UserID       string    `json:"userId"`
	Action       string    `json:"action"`
	Resource     string    `json:"resource"`
	Details      string    `json:"details"`
	Timestamp    time.Time `json:"timestamp"`
	IPAddress    string    `json:"ipAddress"`
	Signature    string    `json:"signature"`
	PreviousHash string    `json:"previousHash"`
}

type AuditManager struct {
	mu          sync.RWMutex
	config      *gateonv1.AuditConfig
	db          *sql.DB
	dialect     db.Dialect
	Broadcaster *Broadcaster
	lastHash    string
	stop        chan struct{}
	stmtInsert  *sql.Stmt
	stmtMu      sync.RWMutex
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
	ch := make(chan AuditEntry, 1000)
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
		manager.prepareStatements()
		go manager.runRetentionTask()
	})
	return err
}

func Stop() {
	if manager != nil {
		close(manager.stop)
		manager.stmtMu.Lock()
		if manager.stmtInsert != nil {
			_ = manager.stmtInsert.Close()
			manager.stmtInsert = nil
		}
		manager.stmtMu.Unlock()
	}
}

func (m *AuditManager) prepareStatements() {
	m.stmtMu.Lock()
	defer m.stmtMu.Unlock()
	query := m.dialect.Rebind("INSERT INTO audit_logs (id, user_id, action, resource, details, timestamp, ip_address, signature, previous_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
	stmt, err := m.db.Prepare(query)
	if err != nil {
		logger.L.LogError("audit: failed to prepare insert statement", "error", err)
		return
	}
	m.stmtInsert = stmt
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

	var err error
	m.stmtMu.RLock()
	stmt := m.stmtInsert
	m.stmtMu.RUnlock()

	if stmt != nil {
		_, err = stmt.ExecContext(ctx, entry.ID, entry.UserID, entry.Action, entry.Resource, entry.Details, entry.Timestamp, entry.IPAddress, entry.Signature, entry.PreviousHash)
	} else {
		// Fallback to unnamed statement if preparation failed
		query := m.dialect.Rebind("INSERT INTO audit_logs (id, user_id, action, resource, details, timestamp, ip_address, signature, previous_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
		_, err = m.db.ExecContext(ctx, query, entry.ID, entry.UserID, entry.Action, entry.Resource, entry.Details, entry.Timestamp, entry.IPAddress, entry.Signature, entry.PreviousHash)
	}

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
	return signEntry(entry, key)
}

// signEntry computes an entry's HMAC. It is a free function, not a method,
// because verification must be possible without an AuditManager — and therefore
// without a database, a config or a running gateway. A verifier that can only
// run inside the process that wrote the log is not much of a verifier.
func signEntry(entry AuditEntry, key string) string {
	payload := fmt.Sprintf("%s|%s|%s|%s|%s|%d|%s|%s", entry.ID, entry.UserID, entry.Action, entry.Resource, entry.Details, entry.Timestamp.Unix(), entry.IPAddress, entry.PreviousHash)
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

// ChainError reports the first break found in an audit chain, identifying the
// entry so an operator can see what was touched rather than only that something
// was.
type ChainError struct {
	Index  int    // position in the slice passed to VerifyChain, oldest-first
	ID     string // the entry's ID, or "" if the break is a missing predecessor
	Reason string
}

func (e *ChainError) Error() string {
	if e.ID == "" {
		return fmt.Sprintf("audit chain broken at index %d: %s", e.Index, e.Reason)
	}
	return fmt.Sprintf("audit chain broken at index %d (entry %s): %s", e.Index, e.ID, e.Reason)
}

// VerifyChain recomputes an audit chain and reports the first break.
//
// This is the half of tamper-evidence that was missing. log() has always signed
// each entry with the configured key and chained it to its predecessor via
// PreviousHash, and the code comment there describes exactly this check — but
// nothing performed it, in Go or in the dashboard, so the signatures were
// written and never read. A log that records evidence nobody checks is not
// tamper-evident; it is a log with two extra columns.
//
// Entries must be ordered oldest-first. Note that GetLogs returns newest-first
// (ORDER BY timestamp DESC), so its result has to be reversed before it is
// passed here.
//
// genesis is the PreviousHash the first entry is expected to carry. Pass "" when
// verifying from the very beginning of the log; pass the signature of the entry
// immediately preceding the slice when verifying a window, which is what makes
// it possible to check a page of history without replaying all of it.
//
// Detects, in one pass: an edited field (the recomputed HMAC stops matching), a
// forged or truncated signature, a deleted entry (its successor's PreviousHash
// no longer resolves), a reordered pair, and an inserted entry (it has no valid
// predecessor). What it cannot detect is an attacker who holds the signing key
// and rewrites the whole chain — the key is the trust anchor, which is why
// SignatureKey belongs somewhere the gateway's own database does not reach.
func VerifyChain(entries []AuditEntry, key string, genesis string) error {
	if key == "" {
		return &ChainError{Index: -1, Reason: "no signature key supplied; the chain cannot be verified"}
	}

	prev := genesis
	for i, entry := range entries {
		if entry.Signature == "" {
			return &ChainError{Index: i, ID: entry.ID, Reason: "entry is unsigned"}
		}
		if entry.PreviousHash != prev {
			return &ChainError{
				Index: i, ID: entry.ID,
				Reason: "previous_hash does not match the preceding entry's signature; an entry was inserted, removed or reordered",
			}
		}
		want := signEntry(entry, key)
		// Constant-time: a verifier is reachable by whoever can submit a log to
		// be checked, and a byte-at-a-time comparison leaks the expected MAC.
		if !hmac.Equal([]byte(entry.Signature), []byte(want)) {
			return &ChainError{
				Index: i, ID: entry.ID,
				Reason: "signature does not match the entry contents; the entry was modified or signed with a different key",
			}
		}
		prev = entry.Signature
	}
	return nil
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
			// Still skipped rather than aborted, so one bad row does not take
			// the whole audit view down — but no longer in silence. An audit
			// trail that quietly returns 9 of 10 entries is worse than one that
			// errors, because nothing distinguishes it from a complete answer.
			logger.L.LogError("audit: skipping an unreadable row while reading logs", "error", err)
			continue
		}
		logs = append(logs, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: reading logs failed: %w", err)
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
	// Generated getters, not field access: m.config is nil whenever a global
	// config is saved with no audit block, because UpdateConfig assigns
	// conf.Audit straight through and that field is simply absent. log() has
	// always guarded for it; this did not, so the next tick dereferenced nil —
	// on runRetentionTask's goroutine, which has no recover, taking the whole
	// process with it. The getters return zero values on a nil receiver, and
	// retentionDays <= 0 below then means "keep everything", which is the right
	// reading of "no audit configuration".
	//
	// RUnlock is deferred rather than called inline for the same reason: the
	// panic happened between RLock and RUnlock and left the mutex read-locked
	// forever, so anything that later took the write lock would have hung even
	// if the process had survived.
	m.mu.RLock()
	cfg := m.config
	m.mu.RUnlock()

	retentionDays := cfg.GetRetentionDays()
	archiveOnRetention := cfg.GetArchiveOnRetention()

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
			// Abort, do not skip. Every row read here is a row checkRetention is
			// about to DELETE. Skipping archived everything except the
			// unreadable entry and then destroyed the original, losing exactly
			// the record something had already gone wrong with.
			return fmt.Errorf("audit: archive aborted, a row could not be read: %w", err)
		}
		logs = append(logs, e)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("audit: archive aborted, reading rows failed: %w", err)
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

	// #nosec G304 -- path is filepath.Join of a fixed archive directory and a
	// name this function just built from two timestamps and a UUID. Nothing
	// attacker-supplied is in it.
	f, err := os.Create(path)
	if err != nil {
		return err
	}

	// No deferred Close on either the file or the compressor. Both flush on
	// Close, and a deferred Close runs after this function has already returned
	// nil — so a failure at flush time (a full disk is the ordinary case) was
	// reported nowhere, checkRetention read success, and it deleted the rows the
	// archive was supposed to be preserving. The archive is the only reason the
	// deletion is safe, so its write has to be checked before saying it worked.
	if writeErr := writeArchive(f, logs); writeErr != nil {
		_ = f.Close()
		// A truncated archive on disk is worse than none: it looks like a
		// backup until someone needs it.
		_ = os.Remove(path)
		return writeErr
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("audit: archive incomplete, closing %s failed: %w", filename, err)
	}

	logger.L.LogInfo("audit: logs archived", "filename", filename, "count", len(logs))
	return nil
}

// writeArchive encodes logs as brotli-compressed JSON into w and flushes.
// Returning the compressor's Close error is the point: it is what emits the
// final block, so it is where a failed write surfaces.
func writeArchive(w io.Writer, logs []AuditEntry) error {
	// Use Brotli for best smallest algorithm as requested
	bw := brotli.NewWriterLevel(w, brotli.BestCompression)

	if err := json.NewEncoder(bw).Encode(logs); err != nil {
		_ = bw.Close()
		return err
	}
	return bw.Close()
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

	// #nosec G304 -- filename is passed through filepath.Base above, which
	// strips every directory component including "..", and is then joined to a
	// fixed archive directory. That is the traversal defence; gosec sees only
	// that a variable reached os.Open.
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
			// See GetLogs: skipped so one bad row cannot break the view, but
			// logged, because the count returned to the caller comes from a
			// separate COUNT(*) and will not match the rows actually returned.
			logger.L.LogError("audit: skipping an unreadable row while paginating logs", "error", err)
			continue
		}
		logs = append(logs, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("audit: reading logs failed: %w", err)
	}
	return logs, total, nil
}
