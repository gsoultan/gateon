// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package waf

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// An exception suppresses one rule for one place.
//
// This is how a false positive is cleared. Under Coraza the same intent was
// expressed by generating a SecLang rule containing ctl:ruleRemoveById, which
// meant the suppression was itself a rule: it had an ID, it appeared in the
// rule list, it could be edited into something else, and its scope was whatever
// the generated directive happened to say.
//
// An exception is a different kind of object and is stored as one. It always
// names the rule it suppresses, it is always scoped, and it always records why
// — because an exception with no rationale is indistinguishable from a mistake
// six months later, and the whole point of the false-positive workflow is that
// somebody will look at this again.
type Exception struct {
	ID string `json:"id"`

	// RuleID is the rule to suppress.
	RuleID uint32 `json:"rule_id"`

	// Path limits the suppression. A trailing "*" makes it a prefix, so
	// "/admin/*" covers a subtree. Empty means every path, which is almost
	// never what anyone wants.
	Path string `json:"path,omitempty"`

	// Target limits it to one collection, by the same names Definition uses.
	Target string `json:"target,omitempty"`

	// Key limits it to one named value: a header, an argument, a JSON field.
	Key string `json:"key,omitempty"`

	// Note records why. It is carried into audit output.
	Note string `json:"note"`

	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

// Compiled converts the stored exception into the engine's form.
func (e Exception) Compiled() (rules.Exception, error) {
	if e.RuleID == 0 {
		return rules.Exception{}, fmt.Errorf(
			"exception %s names no rule; an exception matching every rule would "+
				"disable the whole ruleset", e.ID)
	}
	ex := rules.Exception{
		RuleID: types.RuleID(e.RuleID),
		Path:   e.Path,
		Key:    e.Key,
		Note:   e.Note,
	}
	if e.Target != "" {
		kind, ok := targetKinds[strings.ToLower(strings.TrimSpace(e.Target))]
		if !ok {
			return rules.Exception{}, fmt.Errorf("exception %s: unknown collection %q", e.ID, e.Target)
		}
		ex.Target = kind
	}
	if err := ex.Validate(); err != nil {
		return rules.Exception{}, fmt.Errorf("exception %s: %w", e.ID, err)
	}
	return ex, nil
}

// ExceptionStore persists rule exceptions.
type ExceptionStore struct {
	db          *sql.DB
	dialect     db.Dialect
	mu          sync.RWMutex
	cache       []Exception
	invalidator Invalidator
}

// SetInvalidator registers the hook that rebuilds compiled engines.
//
// Exceptions are compiled into the engine's plan, so adding one has no effect
// until the engine is rebuilt. Without this an operator marks a false positive,
// the dashboard reports success, and the request keeps being blocked.
func (s *ExceptionStore) SetInvalidator(i Invalidator) {
	s.mu.Lock()
	s.invalidator = i
	s.mu.Unlock()
}

func (s *ExceptionStore) notifyInvalidation() {
	s.mu.RLock()
	i := s.invalidator
	s.mu.RUnlock()
	if i != nil {
		i.Invalidate()
	}
}

var globalExceptions *ExceptionStore

// InitExceptionStore initialises the process-wide exception store. It shares
// the rule store's connection: the two are read together on every engine build,
// and a second pool would be two pools where one suffices.
func InitExceptionStore(ctx context.Context) error {
	if globalStore == nil {
		return fmt.Errorf("the WAF rule store must be initialised first")
	}
	globalExceptions = globalStore.Exceptions(ctx)
	return nil
}

// GetExceptionStore returns the process-wide exception store, or nil.
func GetExceptionStore() *ExceptionStore { return globalExceptions }

// Exceptions returns the exception store for this rule store, creating it on
// first use.
//
// It hangs off the rule store because the two are always read together and are
// backed by the same database. Making it lazy here rather than a step the
// caller has to remember is what keeps a differently-wired startup path — the
// end-to-end tests build the server without the command's main function — from
// silently coming up with rule exceptions that never load.
func (s *Store) Exceptions(ctx context.Context) *ExceptionStore {
	s.mu.Lock()
	if s.exceptions == nil {
		s.exceptions = NewExceptionStore(s.db, s.dialect)
	}
	es := s.exceptions
	s.mu.Unlock()

	if err := es.Reload(ctx); err != nil {
		logger.L.LogWarn("failed to load WAF exceptions", "error", err)
	}
	if globalExceptions == nil {
		globalExceptions = es
	}
	return es
}

// NewExceptionStore returns a store over an open database.
func NewExceptionStore(d *sql.DB, dialect db.Dialect) *ExceptionStore {
	return &ExceptionStore{db: d, dialect: dialect}
}

// Reload refreshes the in-memory cache.
func (s *ExceptionStore) Reload(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, rule_id, path, target, key_name, note, enabled, created_at FROM waf_exceptions ORDER BY created_at ASC")
	if err != nil {
		return err
	}
	defer rows.Close()

	var out []Exception
	for rows.Next() {
		var e Exception
		if err := rows.Scan(&e.ID, &e.RuleID, &e.Path, &e.Target, &e.Key,
			&e.Note, &e.Enabled, &e.CreatedAt); err != nil {
			return err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	s.cache = out
	s.mu.Unlock()
	return nil
}

// Add stores an exception and refreshes the cache.
func (s *ExceptionStore) Add(ctx context.Context, e *Exception) error {
	if strings.TrimSpace(e.Note) == "" {
		return fmt.Errorf("an exception must record why it exists")
	}
	if _, err := e.Compiled(); err != nil {
		return err
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now()
	}
	query := s.dialect.Rebind(
		"INSERT INTO waf_exceptions (id, rule_id, path, target, key_name, note, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
	if _, err := s.db.ExecContext(ctx, query,
		e.ID, e.RuleID, e.Path, e.Target, e.Key, e.Note, e.Enabled, e.CreatedAt); err != nil {
		return err
	}
	if err := s.Reload(ctx); err != nil {
		return err
	}
	s.notifyInvalidation()
	return nil
}

// Delete removes an exception.
func (s *ExceptionStore) Delete(ctx context.Context, id string) error {
	query := s.dialect.Rebind("DELETE FROM waf_exceptions WHERE id = ?")
	if _, err := s.db.ExecContext(ctx, query, id); err != nil {
		return err
	}
	if err := s.Reload(ctx); err != nil {
		return err
	}
	s.notifyInvalidation()
	return nil
}

// All returns every stored exception.
func (s *ExceptionStore) All() []Exception {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Exception, len(s.cache))
	copy(out, s.cache)
	return out
}

// Compiled returns the enabled exceptions, and anything that would not compile.
func (s *ExceptionStore) Compiled() ([]rules.Exception, []error) {
	s.mu.RLock()
	cached := make([]Exception, len(s.cache))
	copy(cached, s.cache)
	s.mu.RUnlock()

	out := make([]rules.Exception, 0, len(cached))
	var problems []error
	for _, e := range cached {
		if !e.Enabled {
			continue
		}
		ex, err := e.Compiled()
		if err != nil {
			problems = append(problems, err)
			continue
		}
		out = append(out, ex)
	}
	return out, problems
}
