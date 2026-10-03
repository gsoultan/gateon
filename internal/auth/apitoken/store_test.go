// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package apitoken

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/testutil"
)

// newTestStore is a store on a fresh, migrated SQLite database.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	database, dialect, err := db.Open(filepath.Join(t.TempDir(), "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := db.Migrate(database, dialect); err != nil {
		t.Fatal(err)
	}
	return NewStore(database, dialect)
}

func create(t *testing.T, s *Store, p CreateParams) (Token, string) {
	t.Helper()
	tok, secret, err := s.Create(context.Background(), p)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return tok, secret
}

var scrape = CreateParams{Name: "prometheus", Scopes: []string{"metrics:read"}, CreatedBy: "admin"}

// TestATokenIsStoredOnlyAsItsHash: the secret is returned once and nothing in
// the table can be used in its place.
func TestATokenIsStoredOnlyAsItsHash(t *testing.T) {
	s := newTestStore(t)
	_, secret := create(t, s, scrape)
	if !LooksLikeToken(secret) {
		t.Fatalf("the secret %q does not have a token's shape", secret)
	}
	rows, err := s.db.Query("SELECT id, name, token_hash, hint, scopes, created_by FROM api_tokens")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var cols [6]string
		if err := rows.Scan(&cols[0], &cols[1], &cols[2], &cols[3], &cols[4], &cols[5]); err != nil {
			t.Fatal(err)
		}
		for _, c := range cols {
			if strings.Contains(c, secret[len(Prefix):]) {
				t.Errorf("the table holds the secret: %q", c)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

// TestVerifyAcceptsOnlyAKnownTokenWithTheScope: the scope is checked, and
// every refusal is the same ErrInvalid.
func TestVerifyAcceptsOnlyAKnownTokenWithTheScope(t *testing.T) {
	s := newTestStore(t)
	tok, secret := create(t, s, scrape)
	got, err := s.Verify(context.Background(), secret, ScopeMetricsRead)
	if err != nil || got.ID != tok.ID {
		t.Fatalf("Verify of the issued token: %v, %v", got, err)
	}
	other, _, _ := newSecret()
	for name, try := range map[string]struct {
		secret string
		scope  Scope
	}{
		"another scope":    {secret, Scope("users:write")},
		"an unknown token": {other, ScopeMetricsRead},
		"a session token":  {"v4.local.abc", ScopeMetricsRead},
		"a truncated one":  {secret[:len(secret)-1], ScopeMetricsRead},
	} {
		if _, err := s.Verify(context.Background(), try.secret, try.scope); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

// TestRevokeStopsATokenAtOnce: nothing caches an accepted token.
func TestRevokeStopsATokenAtOnce(t *testing.T) {
	s := newTestStore(t)
	tok, secret := create(t, s, scrape)
	if _, err := s.Verify(context.Background(), secret, ScopeMetricsRead); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(context.Background(), tok.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := s.Verify(context.Background(), secret, ScopeMetricsRead); !errors.Is(err, ErrInvalid) {
		t.Errorf("a revoked token: err = %v, want ErrInvalid", err)
	}
	if err := s.Revoke(context.Background(), tok.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking it again: err = %v, want ErrNotFound", err)
	}
}

// TestATokenExpires and its last use is recorded, to the minute, at most once
// a minute.
func TestATokenExpiresAndRecordsItsLastUse(t *testing.T) {
	s := newTestStore(t)
	now := time.Date(2026, 10, 3, 12, 0, 30, 0, time.UTC)
	s.SetClock(func() time.Time { return now })
	tok, secret := create(t, s, CreateParams{Name: "short", Scopes: []string{"metrics:read"}, TTLDays: 1})
	if tok.ExpiresAt.IsZero() {
		t.Fatal("a token with ttl_days has no expiry")
	}
	if _, err := s.Verify(context.Background(), secret, ScopeMetricsRead); err != nil {
		t.Fatal(err)
	}
	list, _, err := s.List(context.Background(), 0, 10)
	if err != nil || len(list) != 1 {
		t.Fatalf("List: %v %v", list, err)
	}
	if want := now.Truncate(time.Minute); !list[0].LastUsedAt.Equal(want) {
		t.Errorf("last used = %v, want %v", list[0].LastUsedAt, want)
	}
	now = now.Add(24 * time.Hour)
	if _, err := s.Verify(context.Background(), secret, ScopeMetricsRead); !errors.Is(err, ErrInvalid) {
		t.Errorf("an expired token: err = %v, want ErrInvalid", err)
	}
}

// TestCreateRefusesWhatItCannotIssue: names, scopes and expiries are bounded,
// and so is the number of tokens.
func TestCreateRefusesWhatItCannotIssue(t *testing.T) {
	s := newTestStore(t)
	for name, p := range map[string]CreateParams{
		"no name":         {Scopes: []string{"metrics:read"}},
		"a long name":     {Name: strings.Repeat("n", MaxNameLength+1), Scopes: []string{"metrics:read"}},
		"no scope":        {Name: "x"},
		"an unknown one":  {Name: "x", Scopes: []string{"metrics:read", "users:write"}},
		"a negative ttl":  {Name: "x", Scopes: []string{"metrics:read"}, TTLDays: -1},
		"a ten-year+ ttl": {Name: "x", Scopes: []string{"metrics:read"}, TTLDays: MaxTTLDays + 1},
	} {
		if _, _, err := s.Create(context.Background(), p); !errors.Is(err, ErrBadRequest) {
			t.Errorf("%s: err = %v, want ErrBadRequest", name, err)
		}
	}
	for range MaxActive {
		create(t, s, scrape)
	}
	if _, _, err := s.Create(context.Background(), scrape); !errors.Is(err, ErrTooMany) {
		t.Errorf("token %d: err = %v, want ErrTooMany", MaxActive+1, err)
	}
	list, total, err := s.List(context.Background(), 0, 0)
	if err != nil || total != MaxActive || len(list) != MaxActive {
		t.Errorf("List: %d of %d, %v", len(list), total, err)
	}
}

func TestShapeAndBearer(t *testing.T) {
	secret, _, err := newSecret()
	if err != nil {
		t.Fatal(err)
	}
	for header, want := range map[string]bool{
		"Bearer " + secret:            true,
		"bearer " + secret:            true,
		"Bearer v4.local.abc":         false,
		"Basic " + secret:             false,
		"Bearer " + secret + "x":      false,
		"Bearer " + secret[:20] + "!": false,
		"":                            false,
	} {
		if _, got := BearerToken(header); got != want {
			t.Errorf("BearerToken(%q) = %v, want %v", header, got, want)
		}
	}
}

// TestStoreOnPostgres runs the lifecycle on Postgres, whose TIMESTAMP has no
// zone: the expiry and last use must come back as the instants written.
func TestStoreOnPostgres(t *testing.T) {
	dsn := os.Getenv("GATEON_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEON_TEST_POSTGRES_DSN not set")
	}
	testutil.LockPostgres(t, dsn)
	database, dialect, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := db.Migrate(database, dialect); err != nil {
		t.Fatal(err)
	}
	s := NewStore(database, dialect)
	tok, secret := create(t, s, CreateParams{Name: "pg", Scopes: []string{"metrics:read"}, TTLDays: 2})
	t.Cleanup(func() { _ = s.Revoke(context.Background(), tok.ID) })
	got, err := s.Verify(context.Background(), secret, ScopeMetricsRead)
	if err != nil {
		t.Fatalf("Verify on Postgres: %v", err)
	}
	if !got.ExpiresAt.Equal(tok.ExpiresAt) {
		t.Errorf("expiry read back as %v, written as %v", got.ExpiresAt, tok.ExpiresAt)
	}
}
