// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gwaf/rules"
)

type Invalidator interface {
	Invalidate()
}

type Store struct {
	db          *sql.DB
	dialect     db.Dialect
	cache       []Rule
	exceptions  *ExceptionStore
	mu          sync.RWMutex
	invalidator Invalidator
}

var (
	globalStore *Store
	storeOnce   sync.Once
)

// NewStore creates a new WAF rule store.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// NewStoreWithDialect creates a new WAF rule store with a specific dialect.
func NewStoreWithDialect(db *sql.DB, dialect db.Dialect) *Store {
	return &Store{db: db, dialect: dialect}
}

// InitStore initializes the WAF rule store and loads rules into memory.
func InitStore(databaseURL string) error {
	var err error
	storeOnce.Do(func() {
		d, dialect, openErr := db.Open(databaseURL)
		if openErr != nil {
			err = openErr
			return
		}
		globalStore = &Store{db: d, dialect: dialect}
		if migrateErr := db.Migrate(d, dialect); migrateErr != nil {
			logger.L.LogError("failed to migrate WAF rules table", "error", migrateErr)
		}
		if reloadErr := globalStore.Reload(context.Background()); reloadErr != nil {
			logger.L.LogWarn("failed to load initial WAF rules", "error", reloadErr)
		}
		if seedErr := globalStore.Seed(context.Background()); seedErr != nil {
			logger.L.LogWarn("failed to seed WAF rules", "error", seedErr)
		}
		// Exceptions are initialised here rather than by the caller: every
		// engine build reads both, so a rule store without an exception store
		// is never a valid state, and making it the caller's job to remember
		// only creates a startup ordering bug waiting to happen.
		if exErr := InitExceptionStore(context.Background()); exErr != nil {
			logger.L.LogWarn("failed to load WAF exceptions", "error", exErr)
		}
	})
	return err
}

// GetStore returns the global WAF rule store.
func GetStore() *Store {
	return globalStore
}

// Reload refreshes the in-memory cache from the database.
func (s *Store) Reload(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "SELECT id, name, directive, definition, format, conversion_note, enabled, paranoia_level, category, created_at, updated_at FROM waf_rules ORDER BY id ASC")
	if err != nil {
		return err
	}
	defer rows.Close()

	var rules []Rule
	for rows.Next() {
		var r Rule
		if err := rows.Scan(r.scanTargets()...); err != nil {
			return err
		}
		rules = append(rules, r)
	}

	s.mu.Lock()
	s.cache = rules
	s.mu.Unlock()
	return nil
}

// GetEnabledRules returns all currently enabled WAF rules from the cache.
func (s *Store) GetEnabledRules() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var enabled []Rule
	for _, r := range s.cache {
		if r.Enabled {
			enabled = append(enabled, r)
		}
	}
	return enabled
}

// CompiledRules returns the operator-authored rules that apply at the given
// paranoia level, as gwaf rules, along with anything that could not be
// compiled.
//
// A rule that fails to compile is reported rather than dropped silently. The
// two ways it happens are a rule still in SecLang format and a typed rule an
// operator edited into something invalid, and in both cases the operator
// believes they have a protection they do not have — which is the single worst
// state a WAF can be in.
func (s *Store) CompiledRules(paranoiaLevel int) (rules.Set, []RuleError) {
	s.mu.RLock()
	cached := make([]Rule, len(s.cache))
	copy(cached, s.cache)
	s.mu.RUnlock()

	set := make(rules.Set, 0, len(cached))
	var problems []RuleError
	for _, r := range cached {
		if !r.Enabled || r.ParanoiaLevel > paranoiaLevel {
			continue
		}
		rule, err := r.Compiled()
		if err != nil {
			problems = append(problems, RuleError{ID: r.ID, Name: r.Name, Err: err})
			continue
		}
		set = append(set, rule)
	}
	return set, problems
}

// RuleError is a stored rule that could not be turned into an enforceable one.
type RuleError struct {
	ID   string
	Name string
	Err  error
}

func (e RuleError) Error() string { return e.Err.Error() }

func (e RuleError) Unwrap() error { return e.Err }

// GetRule returns a specific rule by ID from the cache.
func (s *Store) GetRule(id string) (Rule, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.cache {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

// GetAllRules returns all WAF rules from the cache.
func (s *Store) GetAllRules() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Return a copy to avoid external modification of cache
	res := make([]Rule, len(s.cache))
	copy(res, s.cache)
	return res
}

// ListRules returns a paginated list of WAF rules from the database with optional search and category filter.
func (s *Store) ListRules(ctx context.Context, limit, offset int, search, category string) ([]Rule, int, error) {
	var rules []Rule
	var total int

	query := "SELECT id, name, directive, definition, format, conversion_note, enabled, paranoia_level, category, created_at, updated_at FROM waf_rules"
	countQuery := "SELECT COALESCE(COUNT(*), 0) FROM waf_rules"
	var args []any
	var conditions []string

	if search != "" {
		conditions = append(conditions, "(id = ? OR id LIKE ? OR name LIKE ? OR definition LIKE ? OR category LIKE ?)")
		searchArg := "%" + search + "%"
		args = append(args, search, searchArg, searchArg, searchArg, searchArg)
	}

	if category != "" && category != "all" {
		conditions = append(conditions, "category = ?")
		args = append(args, category)
	}

	if len(conditions) > 0 {
		where := " WHERE " + strings.Join(conditions, " AND ")
		query += where
		countQuery += where
	}

	// Get total count
	var totalCount sql.NullInt64
	err := s.db.QueryRowContext(ctx, s.dialect.Rebind(countQuery), args...).Scan(&totalCount)
	if err != nil {
		return nil, 0, err
	}
	total = int(totalCount.Int64)

	// Sort by numeric ID if it looks like a number, else lexicographically.
	// This ensures that rule 900 comes before 1000.
	if s.dialect.Driver == db.DriverSQLite {
		query += " ORDER BY (id+0) ASC, id ASC"
	} else if s.dialect.Driver == db.DriverPostgres {
		// Postgres: try to cast to integer for sorting if numeric, otherwise sort as text
		query += " ORDER BY CASE WHEN id ~ '^[0-9]+$' THEN CAST(id AS INTEGER) ELSE 999999999 END ASC, id ASC"
	} else {
		query += " ORDER BY id ASC"
	}
	if limit > 0 {
		query += " LIMIT ? OFFSET ?"
		args = append(args, limit, offset)
	}

	rows, err := s.db.QueryContext(ctx, s.dialect.Rebind(query), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	for rows.Next() {
		var r Rule
		if err := rows.Scan(r.scanTargets()...); err != nil {
			return nil, 0, err
		}
		rules = append(rules, r)
	}

	return rules, total, nil
}

func (s *Store) SetInvalidator(i Invalidator) {
	s.mu.Lock()
	s.invalidator = i
	s.mu.Unlock()
}

func (s *Store) notifyInvalidation() {
	s.mu.RLock()
	i := s.invalidator
	s.mu.RUnlock()
	if i != nil {
		i.Invalidate()
	}
}

// AddRule inserts a new rule into the database and reloads the cache.
func (s *Store) AddRule(ctx context.Context, r *Rule) error {
	if r.ID == "" {
		r.ID = uuid.New().String()
	}
	now := time.Now()
	query := s.dialect.Rebind("INSERT INTO waf_rules (id, name, directive, definition, format, conversion_note, enabled, paranoia_level, category, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	_, err := s.db.ExecContext(ctx, query,
		r.ID, r.Name, r.Directive, r.Definition, r.Format, r.ConversionNote,
		r.Enabled, r.ParanoiaLevel, r.Category, now, now)
	if err != nil {
		return err
	}
	r.CreatedAt = now
	r.UpdatedAt = now
	if err := s.Reload(ctx); err != nil {
		return err
	}
	s.notifyInvalidation()
	return nil
}

// UpdateRule updates an existing rule in the database and reloads the cache.
func (s *Store) UpdateRule(ctx context.Context, r *Rule) error {
	now := time.Now()
	query := s.dialect.Rebind("UPDATE waf_rules SET name = ?, directive = ?, definition = ?, format = ?, conversion_note = ?, enabled = ?, paranoia_level = ?, category = ?, updated_at = ? WHERE id = ?")
	_, err := s.db.ExecContext(ctx, query,
		r.Name, r.Directive, r.Definition, r.Format, r.ConversionNote,
		r.Enabled, r.ParanoiaLevel, r.Category, now, r.ID)
	if err != nil {
		return err
	}
	r.UpdatedAt = now
	if err := s.Reload(ctx); err != nil {
		return err
	}
	s.notifyInvalidation()
	return nil
}

// DeleteRule removes a rule from the database and reloads the cache.
func (s *Store) DeleteRule(ctx context.Context, id string) error {
	query := s.dialect.Rebind("DELETE FROM waf_rules WHERE id = ?")
	_, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	if err := s.Reload(ctx); err != nil {
		return err
	}
	s.notifyInvalidation()
	return nil
}

// Seed is retained as a no-op.
//
// gateon's default rules used to be seeded here as 75 SecLang directives. They
// are now compiled into the binary (see ruleset.go), which means they are code
// gateon tests rather than data every install carries a drifting copy of, and
// upgrading gateon upgrades them. Migration 60 removes the seeded rows.
//
// The method stays so that callers do not have to care, and because a Seed that
// silently reintroduced 75 rows on the next start would undo the migration.
func (s *Store) Seed(ctx context.Context) error {
	if err := s.Reload(ctx); err != nil {
		return err
	}
	s.notifyInvalidation()
	return nil
}
