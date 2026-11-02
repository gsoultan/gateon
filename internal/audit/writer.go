// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package audit

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/logger"
)

// The system entries the gateway writes for itself -- one for every security
// threat -- went through log, which inserts one row and waits for it. It ran on
// the telemetry writer goroutine, so under attack every threat cost that
// goroutine an INSERT and, on SQLite, a commit; threats queued behind it and
// were dropped when their channel filled. LogSystem hands the entry to a
// writer of its own instead, which signs and stores whatever is queued in one
// transaction.

const (
	// systemQueueSize bounds the system entries waiting to be written. Past it
	// an entry is dropped and counted (DroppedSystemEntries): the threat it
	// records is stored in security_threats regardless, and an audit queue the
	// attacker could grow without bound would turn their flood into our memory.
	systemQueueSize = 4096
	// systemBatchSize bounds the entries one transaction writes.
	systemBatchSize = 256
	// dropWarnEvery is how many drops pass between two warnings.
	dropWarnEvery = 1000
)

// systemEntry is one queued LogSystem call, before it is signed.
type systemEntry struct {
	action, resource, details, ip string
}

var droppedSystemEntries atomic.Uint64

// DroppedSystemEntries is how many system entries were dropped because the
// writer was behind.
func DroppedSystemEntries() uint64 { return droppedSystemEntries.Load() }

// LogSystem records an entry the gateway makes for itself, user "system",
// without waiting for it to be stored. It never blocks: when the writer is
// that far behind the entry is dropped and counted. A manager with no writer,
// which only a test builds, writes it at once.
func LogSystem(action, resource, details, ip string) {
	m := manager
	if m == nil {
		return
	}
	m.logSystem(systemEntry{action: action, resource: resource, details: details, ip: ip})
}

func (m *AuditManager) logSystem(e systemEntry) {
	if m.queue == nil {
		m.log(context.Background(), "system", e.action, e.resource, e.details, e.ip)
		return
	}
	select {
	case m.queue <- e:
	default:
		if n := droppedSystemEntries.Add(1); n%dropWarnEvery == 1 {
			logger.L.LogWarn("audit: system entries dropped, the writer is behind", "dropped_total", n)
		}
	}
}

// startWriter starts the goroutine that stores queued system entries.
func (m *AuditManager) startWriter() {
	m.queue = make(chan systemEntry, systemQueueSize)
	m.flushReq = make(chan chan struct{})
	m.writerDone = make(chan struct{})
	go m.runWriter()
}

// runWriter stores queued entries a batch at a time until stop is closed,
// then stores what is still queued and returns.
func (m *AuditManager) runWriter() {
	defer close(m.writerDone)
	batch := make([]systemEntry, 0, systemBatchSize)
	for {
		select {
		case e := <-m.queue:
			batch = m.fill(append(batch, e))
			m.writeSystem(batch)
			batch = batch[:0]
		case ack := <-m.flushReq:
			for len(m.queue) > 0 {
				m.writeSystem(m.fill(batch))
				batch = batch[:0]
			}
			close(ack)
		case <-m.stop:
			for len(m.queue) > 0 {
				m.writeSystem(m.fill(batch))
				batch = batch[:0]
			}
			return
		}
	}
}

// fill adds what is already queued to batch, up to systemBatchSize.
func (m *AuditManager) fill(batch []systemEntry) []systemEntry {
	for len(batch) < systemBatchSize {
		select {
		case e := <-m.queue:
			batch = append(batch, e)
		default:
			return batch
		}
	}
	return batch
}

// Flush waits until every system entry queued before it is stored. Shutdown
// and tests use it.
func Flush() {
	m := manager
	if m == nil || m.flushReq == nil {
		return
	}
	ack := make(chan struct{})
	select {
	case m.flushReq <- ack:
		<-ack
	case <-m.writerDone:
	}
}

// writeSystem signs batch in order and stores it in one transaction. The
// entries are signed under mu at the moment they are written, so the chain
// is in the order they are stored and an entry still queued at a crash was
// never part of it.
func (m *AuditManager) writeSystem(batch []systemEntry) {
	if len(batch) == 0 {
		return
	}
	entries, prevHash, ok := m.signSystem(batch)
	if !ok {
		return
	}
	if err := m.insertAll(entries); err != nil {
		// Nothing was stored, so the chain goes on from where it was: the
		// next entry's previous_hash is the last one that is in the log.
		m.mu.Lock()
		if m.lastHash == entries[len(entries)-1].Signature {
			m.lastHash = prevHash
		}
		m.mu.Unlock()
		logger.L.LogError("audit: failed to write system entries", "error", err, "count", len(entries))
		return
	}
	m.noteStored(entries[len(entries)-1])
	if m.Broadcaster != nil {
		for _, e := range entries {
			m.Broadcaster.Broadcast(e)
		}
	}
}

// signSystem turns batch into signed, chained entries, and returns the hash
// the chain had before them. ok is false when auditing is off.
func (m *AuditManager) signSystem(batch []systemEntry) (entries []AuditEntry, prevHash string, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg := m.config
	if cfg != nil && !cfg.Enabled {
		return nil, "", false
	}
	prevHash = m.lastHash
	entries = make([]AuditEntry, len(batch))
	for i, e := range batch {
		entry := AuditEntry{
			ID:           uuid.NewString(),
			UserID:       "system",
			Action:       db.SafeText(e.action),
			Resource:     db.SafeText(e.resource),
			Details:      db.SafeText(e.details),
			Timestamp:    m.nextStamp(),
			IPAddress:    db.SafeText(e.ip),
			PreviousHash: m.lastHash,
		}
		if cfg != nil && cfg.SignEntries && cfg.SignatureKey != "" {
			entry.Signature = m.sign(entry, cfg.SignatureKey)
		}
		m.lastHash = entry.Signature
		entries[i] = entry
	}
	return entries, prevHash, true
}

// nextStamp is the timestamp of the entry signed now: the clock, held to at
// least a microsecond past the previous entry's. Postgres keeps microseconds,
// and the chain is read back in timestamp order, so a batch signed within one
// microsecond would read back in an order the chain does not have. Called
// under mu.
func (m *AuditManager) nextStamp() time.Time {
	t := time.Now().Truncate(time.Microsecond)
	if !t.After(m.lastStamp) {
		t = m.lastStamp.Add(time.Microsecond)
	}
	m.lastStamp = t
	return t
}

// insertAll stores entries in one transaction.
func (m *AuditManager) insertAll(entries []AuditEntry) error {
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare(m.dialect.Rebind(insertAuditQuery))
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		if _, err := stmt.Exec(e.ID, e.UserID, e.Action, e.Resource, e.Details, e.Timestamp, e.IPAddress, e.Signature, e.PreviousHash); err != nil {
			return err
		}
	}
	return tx.Commit()
}
