// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/testutil"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// engineManager is a Manager on one of the two engines gateon supports.
type engineManager struct {
	engine string
	m      *Manager
}

// onEveryEngine runs fn against a Manager on a private SQLite database and,
// when GATEON_TEST_POSTGRES_DSN is set, against one on Postgres. The Postgres
// database is shared with every other test in the module, so accounts made
// through engineManager.create carry a unique name and are removed afterwards.
func onEveryEngine(t *testing.T, fn func(t *testing.T, e engineManager)) {
	t.Helper()
	t.Run("sqlite", func(t *testing.T) {
		fn(t, engineManager{engine: "sqlite", m: managerOn(t, filepath.Join(t.TempDir(), "auth.db"))})
	})
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("GATEON_TEST_POSTGRES_DSN")
		if dsn == "" {
			t.Skip("GATEON_TEST_POSTGRES_DSN not set")
		}
		testutil.LockPostgres(t, dsn)
		fn(t, engineManager{engine: "postgres", m: managerOn(t, dsn)})
	})
}

func managerOn(t *testing.T, databaseURL string) *Manager {
	t.Helper()
	m, err := NewManager(databaseURL, "test-secret-key-32-bytes-minimum!", logger.Default())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// name returns base made unique to this run, so tests sharing one Postgres
// database cannot meet each other's accounts.
func (e engineManager) name(base string) string {
	return base + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

// create adds an account through the create path and removes it when the test
// ends, returning its id.
func (e engineManager) create(t *testing.T, username, password, role string) string {
	t.Helper()
	u := &gateonv1.User{Username: username, Password: password, Role: role}
	if err := e.m.UpsertUser(u); err != nil {
		t.Fatalf("creating %s: %v", username, err)
	}
	t.Cleanup(func() { _ = e.m.DeleteUser(u.Id) })
	return u.Id
}

// signIn returns a session token for username, failing the test if there is none.
func (e engineManager) signIn(t *testing.T, username, password string) string {
	t.Helper()
	token, _, err := e.m.Authenticate(username, password)
	if err != nil || token == "" {
		t.Fatalf("signing in as %s: token %q, err %v", username, token, err)
	}
	return token
}
