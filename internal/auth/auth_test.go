package auth

import (
	"database/sql"
	"os"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func TestAccountLockout(t *testing.T) {
	dbPath := "test_auth.db"
	defer os.Remove(dbPath)

	m, err := NewManager(dbPath, "12345678901234567890123456789012")
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	defer m.Close()

	user := &gateonv1.User{
		Username: "admin",
		Password: "password",
		Role:     RoleAdmin,
	}
	if err := m.UpsertUser(user); err != nil {
		t.Fatalf("failed to upsert user: %v", err)
	}

	// Fail login MaxFailedAttempts times
	for i := 0; i < MaxFailedAttempts; i++ {
		_, _, err := m.Authenticate("admin", "wrong")
		if err != ErrInvalidCredentials {
			t.Errorf("expected ErrInvalidCredentials, got %v", err)
		}
	}

	// Next attempt should be locked
	_, _, err = m.Authenticate("admin", "password")
	if err != ErrAccountLocked {
		t.Errorf("expected ErrAccountLocked, got %v", err)
	}

	// Verify locked_until is set in DB
	var lockedUntil sql.NullTime
	err = m.db.QueryRow("SELECT locked_until FROM users WHERE username = ?", "admin").Scan(&lockedUntil)
	if err != nil {
		t.Fatalf("failed to query locked_until: %v", err)
	}
	if !lockedUntil.Valid {
		t.Error("expected locked_until to be valid")
	}
	if lockedUntil.Time.Before(time.Now()) {
		t.Error("expected locked_until to be in the future")
	}

	// Reset failed attempts by successful login (not possible while locked, so we manually reset for test)
	m.resetFailedAttempts("admin")

	_, _, err = m.Authenticate("admin", "password")
	if err != nil {
		t.Errorf("expected successful login, got %v", err)
	}
}
