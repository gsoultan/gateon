package server

import (
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
)

// TestWithAuthManager_NilDoesNotCreateNonNilInterface is a regression test for the bug where
// WithAuthManager(nil) assigned a nil *auth.Manager to the auth.Service interface, producing a
// non-nil interface with a nil underlying value. This caused ApiService.Setup to skip manager
// initialization (s.Auth == nil was false), then panic on the first method call.
func TestWithAuthManager_NilDoesNotCreateNonNilInterface(t *testing.T) {
	t.Run("nil manager leaves AuthManager as true nil interface", func(t *testing.T) {
		s, err := NewServer(WithAuthManager(nil))
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		if s.AuthManager != nil {
			t.Error("WithAuthManager(nil) must leave AuthManager as nil interface, got non-nil")
		}
	})

	t.Run("non-nil manager sets AuthManager correctly", func(t *testing.T) {
		mgr, err := auth.NewManager("sqlite::memory:", "test-secret-key-32-bytes-minimum!")
		if err != nil {
			t.Fatalf("auth.NewManager: %v", err)
		}
		defer mgr.Close()

		s, err := NewServer(WithAuthManager(mgr))
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		if s.AuthManager == nil {
			t.Error("WithAuthManager(non-nil) must set AuthManager, got nil")
		}
	})
}
