// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// The window VerifyRange checks in one call. A whole log is checked a window
// at a time, each continuing after the last entry of the one before, so a
// verification is bounded work however long the log is (ADR 0050).
const (
	DefaultVerifyLimit = 1000
	MaxVerifyLimit     = 5000
)

var (
	// ErrSigningOff refuses a verification when entries are not being signed:
	// there is no chain to check, and no key to check it with.
	ErrSigningOff = errors.New("audit signing is off, so there is no chain to verify; turn on audit.sign_entries")
	// ErrUnknownCursor refuses an after_id that names no entry, which is what
	// retention deleting it looks like.
	ErrUnknownCursor = errors.New("after_id names no audit entry; start again from a time")
	// ErrNotInitialized answers before the audit manager exists.
	ErrNotInitialized = errors.New("audit manager not initialized")
)

// VerifyRequest names a window of the audit log: from From (zero is the
// beginning) or after the entry AfterID, to To (zero is now), at most Limit
// entries (zero is DefaultVerifyLimit, more than MaxVerifyLimit is that).
type VerifyRequest struct {
	From    time.Time
	To      time.Time
	AfterID string
	Limit   int
}

// VerifyResult is what one window showed.
type VerifyResult struct {
	// Checked is how many entries were found intact.
	Checked int
	// Break is the first entry the chain does not account for, or nil.
	Break   *ChainError
	BreakAt time.Time
	// NextAfterID continues the range; "" when it is complete or broken.
	NextAfterID string
	Complete    bool
	// Last is the newest entry checked; zero when none was.
	Last time.Time
	// TailAnchor is the time of the tail anchor checked (see checkTail); zero
	// when none was.
	TailAnchor time.Time
	// TailMissing is true when the anchor is no longer in the log and retention
	// cannot have removed it: entries were deleted from the end.
	TailMissing bool
}

// VerifyRange checks the HMAC chain over one window of the stored log, oldest
// first, with the configured signature key.
//
// VerifyChain existed and nothing called it, so the chain was computed and
// never checked. This reads the window, chains its first entry to the one
// stored before it, and reports the first entry that does not follow.
func VerifyRange(ctx context.Context, req VerifyRequest) (VerifyResult, error) {
	m := manager
	if m == nil {
		return VerifyResult{}, ErrNotInitialized
	}
	key := m.signingKey()
	if key == "" {
		return VerifyResult{}, ErrSigningOff
	}
	limit := req.Limit
	if limit <= 0 {
		limit = DefaultVerifyLimit
	}
	limit = min(limit, MaxVerifyLimit)
	genesis, entries, err := m.window(ctx, req, limit+1)
	if err != nil {
		return VerifyResult{}, err
	}
	more := len(entries) > limit
	if more {
		entries = entries[:limit]
	}
	orderTies(entries, genesis)
	res := verdict(entries, key, genesis, more)
	if res.Complete && res.Break == nil && req.To.IsZero() {
		if err := m.checkTail(ctx, &res); err != nil {
			return VerifyResult{}, err
		}
	}
	return res, nil
}

// checkTail looks for the tail anchor -- the newest entry this gateway has
// written, or found newest when it started -- in the log (ADR 0057).
//
// A chain cannot show that entries were removed from its end: what is left
// still verifies, and the dashboard said "The audit log verifies" over a log
// whose newest entries had been deleted. The next entry written would break
// the chain, but until then nothing did. The anchor closes that gap for as
// long as this process runs. It cannot close it across a restart: the anchor
// is then read from the log, truncated or not.
//
// An anchor older than the retention period is not looked for: retention may
// have deleted it, and that is not tampering.
func (m *AuditManager) checkTail(ctx context.Context, res *VerifyResult) error {
	m.mu.RLock()
	id, at, days := m.anchorID, m.anchorAt, m.config.GetRetentionDays()
	m.mu.RUnlock()
	if id == "" || (days > 0 && at.Before(time.Now().AddDate(0, 0, -int(days)))) {
		return nil
	}
	var one int
	err := m.db.QueryRowContext(ctx, m.dialect.Rebind("SELECT 1 FROM audit_logs WHERE id = ?"), id).Scan(&one)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		res.TailMissing = true
	case err != nil:
		return fmt.Errorf("audit: look for the newest entry written: %w", err)
	}
	res.TailAnchor = at
	return nil
}

func verdict(entries []AuditEntry, key, genesis string, more bool) VerifyResult {
	var res VerifyResult
	var ce *ChainError
	if err := VerifyChain(entries, key, genesis); errors.As(err, &ce) {
		res.Checked, res.Break, res.BreakAt = ce.Index, ce, entries[ce.Index].Timestamp
		return res
	}
	res.Checked = len(entries)
	if len(entries) > 0 {
		res.Last = entries[len(entries)-1].Timestamp
	}
	if more {
		res.NextAfterID = entries[len(entries)-1].ID
	} else {
		res.Complete = true
	}
	return res
}

// signingKey is the key entries are signed with now, or "" when they are not.
func (m *AuditManager) signingKey() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.config.GetSignEntries() {
		return ""
	}
	return m.config.GetSignatureKey()
}

const entryColumns = "id, user_id, action, resource, details, timestamp, ip_address, signature, previous_hash"

// window reads up to n entries of req's window, oldest first, and the
// signature of the entry stored just before them -- the previous_hash the
// first of them must carry.
func (m *AuditManager) window(ctx context.Context, req VerifyRequest, n int) (string, []AuditEntry, error) {
	start := m.startFrom
	if req.AfterID != "" {
		start = m.startAfter
	}
	genesis, where, args, err := start(ctx, req)
	if err != nil {
		return "", nil, err
	}
	if !req.To.IsZero() {
		where += " AND timestamp <= ?"
		args = append(args, storedForm(req.To))
	}
	args = append(args, n)
	// #nosec G202 -- every part of the statement is a constant of this file;
	// every value is bound.
	entries, err := m.readEntries(ctx, "SELECT "+entryColumns+" FROM audit_logs"+where+" ORDER BY timestamp, id LIMIT ?", args)
	return genesis, entries, err
}

// startAfter begins a window after the entry req.AfterID: the genesis is its
// signature, and the window is everything stored after it.
func (m *AuditManager) startAfter(ctx context.Context, req VerifyRequest) (string, string, []any, error) {
	var genesis string
	err := m.db.QueryRowContext(ctx, m.dialect.Rebind("SELECT signature FROM audit_logs WHERE id = ?"), req.AfterID).
		Scan(&genesis)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil, ErrUnknownCursor
	}
	if err != nil {
		return "", "", nil, fmt.Errorf("audit: read the window's start: %w", err)
	}
	// Compared with the stored value, never a re-bound copy of it, so a
	// driver's time formatting cannot make the cursor miss itself.
	where := " WHERE (timestamp > (SELECT timestamp FROM audit_logs WHERE id = ?)" +
		" OR (timestamp = (SELECT timestamp FROM audit_logs WHERE id = ?) AND id > ?))"
	return genesis, where, []any{req.AfterID, req.AfterID, req.AfterID}, nil
}

// startFrom begins a window at req.From, or at the beginning of the log.
func (m *AuditManager) startFrom(ctx context.Context, req VerifyRequest) (string, string, []any, error) {
	genesis, err := m.signatureBefore(ctx, req.From)
	if err != nil || req.From.IsZero() {
		return genesis, " WHERE 1 = 1", nil, err
	}
	return genesis, " WHERE timestamp >= ?", []any{storedForm(req.From)}, nil
}

// storedForm is t as the log stores its timestamps: in the gateway's local
// zone, which is what time.Now() in log() gives. SQLite keeps a time as text
// and Postgres's TIMESTAMP keeps the wall clock without its offset, so on both
// a bound is only compared correctly in the zone the entries were written in;
// a UTC bound against local text selected the wrong entries entirely.
func storedForm(t time.Time) time.Time { return t.In(time.Local) }

// signatureBefore is the signature of the newest entry stored before from,
// "" when there is none -- the chain starts there.
func (m *AuditManager) signatureBefore(ctx context.Context, from time.Time) (string, error) {
	if from.IsZero() {
		return "", nil
	}
	var sig string
	err := m.db.QueryRowContext(ctx, m.dialect.Rebind(
		"SELECT signature FROM audit_logs WHERE timestamp < ? ORDER BY timestamp DESC, id DESC LIMIT 1"), storedForm(from)).Scan(&sig)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("audit: read the entry before the window: %w", err)
	}
	return sig, nil
}

func (m *AuditManager) readEntries(ctx context.Context, query string, args []any) ([]AuditEntry, error) {
	rows, err := m.db.QueryContext(ctx, m.dialect.Rebind(query), args...)
	if err != nil {
		return nil, fmt.Errorf("audit: read the window: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.UserID, &e.Action, &e.Resource, &e.Details, &e.Timestamp,
			&e.IPAddress, &e.Signature, &e.PreviousHash); err != nil {
			// Not skipped, as the listing does: an entry that cannot be read
			// cannot be shown to be intact.
			return nil, fmt.Errorf("audit: an entry in the window could not be read: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// orderTies puts entries that share a timestamp into chain order. The window
// is read in (timestamp, id) order, and two entries written in the same clock
// tick are ordered by their random ids, not by which was written first; the
// chain itself says which follows which.
func orderTies(entries []AuditEntry, genesis string) {
	prev := genesis
	for i := range entries {
		if entries[i].PreviousHash != prev {
			for j := i + 1; j < len(entries) && entries[j].Timestamp.Equal(entries[i].Timestamp); j++ {
				if entries[j].PreviousHash == prev {
					entries[i], entries[j] = entries[j], entries[i]
					break
				}
			}
		}
		prev = entries[i].Signature
	}
}
