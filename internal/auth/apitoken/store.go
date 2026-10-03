// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package apitoken

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/db"
)

// Statements, rebound per dialect. Every value is bound.
const (
	// #nosec G101 -- a parameterised statement naming a column, not a credential.
	queryInsert = `INSERT INTO api_tokens (id, name, token_hash, hint, scopes, created_by, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	queryCount = `SELECT COUNT(*) FROM api_tokens`
	queryList  = `SELECT id, name, hint, scopes, created_by, created_at, last_used_at, expires_at
		FROM api_tokens ORDER BY created_at DESC, id LIMIT ? OFFSET ?`
	// #nosec G101 -- a parameterised statement naming a column, not a credential.
	queryByHash = `SELECT id, name, hint, scopes, created_by, created_at, last_used_at, expires_at
		FROM api_tokens WHERE token_hash = ?`
	queryDelete = `DELETE FROM api_tokens WHERE id = ?`
	queryTouch  = `UPDATE api_tokens SET last_used_at = ? WHERE id = ?`
)

// touchEvery is how often a token's last use is written: a scrape every
// fifteen seconds would otherwise be a write every fifteen seconds.
const touchEvery = time.Minute

// Store keeps tokens in the management database.
type Store struct {
	db      *sql.DB
	dialect db.Dialect
	now     func() time.Time

	// touched is when each token's last use was last written. Keyed by token
	// id, which only a stored token has, and cleared past MaxActive*4 entries,
	// so it is bounded by the table, not by anything a caller sends.
	mu      sync.Mutex
	touched map[string]time.Time
}

// NewStore keeps tokens in database, whose schema db.Migrate has brought to
// migration 67 or later.
func NewStore(database *sql.DB, dialect db.Dialect) *Store {
	return &Store{db: database, dialect: dialect, now: time.Now, touched: map[string]time.Time{}}
}

// SetClock replaces the clock, for tests.
func (s *Store) SetClock(now func() time.Time) { s.now = now }

// CreateParams describe a token to issue.
type CreateParams struct {
	Name      string
	Scopes    []string
	CreatedBy string
	TTLDays   int
}

// Create issues a token and returns it with its secret, which is not kept.
func (s *Store) Create(ctx context.Context, p CreateParams) (Token, string, error) {
	tok, err := s.validate(p)
	if err != nil {
		return Token{}, "", err
	}
	var n int
	if err := s.db.QueryRowContext(ctx, s.dialect.Rebind(queryCount)).Scan(&n); err != nil {
		return Token{}, "", fmt.Errorf("count api tokens: %w", err)
	}
	if n >= MaxActive {
		return Token{}, "", ErrTooMany
	}
	secret, hash, err := newSecret()
	if err != nil {
		return Token{}, "", err
	}
	tok.Hint = hintOf(secret)
	var expires any
	if !tok.ExpiresAt.IsZero() {
		expires = tok.ExpiresAt
	}
	if _, err := s.db.ExecContext(ctx, s.dialect.Rebind(queryInsert), tok.ID, tok.Name, hash, tok.Hint,
		joinScopes(tok.Scopes), tok.CreatedBy, tok.CreatedAt, expires); err != nil {
		return Token{}, "", fmt.Errorf("store api token: %w", err)
	}
	return tok, secret, nil
}

// validate turns p into the token it describes, or refuses it.
func (s *Store) validate(p CreateParams) (Token, error) {
	name := strings.TrimSpace(p.Name)
	if name == "" || len(name) > MaxNameLength {
		return Token{}, fmt.Errorf("%w: a name of 1 to %d characters is required", ErrBadRequest, MaxNameLength)
	}
	scopes, ok := ParseScopes(p.Scopes)
	if !ok {
		return Token{}, fmt.Errorf("%w: scopes must be one or more of %s", ErrBadRequest, joinScopes(Scopes))
	}
	if p.TTLDays < 0 || p.TTLDays > MaxTTLDays {
		return Token{}, fmt.Errorf("%w: ttl_days must be 0 (no expiry) to %d", ErrBadRequest, MaxTTLDays)
	}
	now := s.now().UTC().Truncate(time.Second)
	tok := Token{ID: uuid.NewString(), Name: name, Scopes: scopes, CreatedBy: p.CreatedBy, CreatedAt: now}
	if p.TTLDays > 0 {
		tok.ExpiresAt = now.Add(time.Duration(p.TTLDays) * 24 * time.Hour)
	}
	return tok, nil
}

// List returns a page of tokens, newest first, and how many there are.
func (s *Store) List(ctx context.Context, page, pageSize int) ([]Token, int, error) {
	if pageSize <= 0 || pageSize > MaxActive {
		pageSize = MaxActive
	}
	page = max(page, 0)
	var total int
	if err := s.db.QueryRowContext(ctx, s.dialect.Rebind(queryCount)).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count api tokens: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, s.dialect.Rebind(queryList), pageSize, page*pageSize)
	if err != nil {
		return nil, 0, fmt.Errorf("list api tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]Token, 0, pageSize)
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, t)
	}
	return out, total, rows.Err()
}

// Revoke deletes token id. It stops working at once: Verify reads the table.
func (s *Store) Revoke(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, s.dialect.Rebind(queryDelete), id)
	if err != nil {
		return fmt.Errorf("revoke api token: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrNotFound
	}
	s.mu.Lock()
	delete(s.touched, id)
	s.mu.Unlock()
	return nil
}

// Verify returns the token secret is, if it exists, has not expired and
// carries scope, and records its use. Every refusal is ErrInvalid.
func (s *Store) Verify(ctx context.Context, secret string, scope Scope) (Token, error) {
	if !LooksLikeToken(secret) {
		return Token{}, ErrInvalid
	}
	row := s.db.QueryRowContext(ctx, s.dialect.Rebind(queryByHash), hashOf(secret))
	tok, err := scanToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, ErrInvalid
	}
	if err != nil {
		return Token{}, fmt.Errorf("look up api token: %w", err)
	}
	now := s.now()
	if tok.Expired(now) || !tok.Allows(scope) {
		return Token{}, ErrInvalid
	}
	s.touch(ctx, tok.ID, now)
	return tok, nil
}

// touch writes id's last use, at most once per touchEvery. A failed write is
// not a refusal: the scrape was authorised either way.
func (s *Store) touch(ctx context.Context, id string, now time.Time) {
	s.mu.Lock()
	if last, ok := s.touched[id]; ok && now.Sub(last) < touchEvery {
		s.mu.Unlock()
		return
	}
	if len(s.touched) >= MaxActive*4 {
		clear(s.touched)
	}
	s.touched[id] = now
	s.mu.Unlock()
	_, _ = s.db.ExecContext(ctx, s.dialect.Rebind(queryTouch), now.UTC().Truncate(time.Minute), id)
}

type scanner interface{ Scan(dest ...any) error }

func scanToken(r scanner) (Token, error) {
	var t Token
	var scopes string
	var lastUsed, expires sql.NullTime
	if err := r.Scan(&t.ID, &t.Name, &t.Hint, &scopes, &t.CreatedBy, &t.CreatedAt, &lastUsed, &expires); err != nil {
		return Token{}, err
	}
	t.Scopes = splitScopes(scopes)
	if lastUsed.Valid {
		t.LastUsedAt = lastUsed.Time
	}
	if expires.Valid {
		t.ExpiresAt = expires.Time
	}
	return t, nil
}
