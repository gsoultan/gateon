// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/logger"
)

// TestWithAuthManager_NilIsUnusableNotUnsafe covers the bug where
// WithAuthManager(nil) assigned a nil *auth.Manager to the auth.Service
// interface, producing a non-nil interface with a nil underlying value. That
// made ApiService.Setup skip manager initialization (s.Auth == nil was false)
// and then panic on the first method call.
//
// AuthManager is now always an *auth.Holder, so the invariant under test is no
// longer "the interface is nil" — it is "no service is available, and calling
// through anyway denies instead of panicking". Those are the two properties the
// original bug violated.
func TestWithAuthManager_NilIsUnusableNotUnsafe(t *testing.T) {
	t.Run("nil manager yields an unavailable auth service", func(t *testing.T) {
		s, err := NewServer(WithAuthManager(nil))
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		if auth.Available(s.AuthManager) {
			t.Error("WithAuthManager(nil) must leave auth unavailable")
		}
	})

	t.Run("calling an unavailable service denies rather than panicking", func(t *testing.T) {
		s, err := NewServer(WithAuthManager(nil))
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		claims, err := s.AuthManager.VerifyToken("any-token")
		if err == nil {
			t.Fatal("VerifyToken on an unavailable service must return an error, not admit the request")
		}
		if claims != nil {
			t.Errorf("VerifyToken must not return claims when unavailable, got %v", claims)
		}
		if s.AuthManager.IsSetupDone() {
			t.Error("IsSetupDone must be false when no service is installed")
		}
	})

	t.Run("non-nil manager sets AuthManager correctly", func(t *testing.T) {
		mgr, err := auth.NewManager("sqlite::memory:", "test-secret-key-32-bytes-minimum!", logger.Default())
		if err != nil {
			t.Fatalf("auth.NewManager: %v", err)
		}
		defer mgr.Close()

		s, err := NewServer(WithAuthManager(mgr))
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		if !auth.Available(s.AuthManager) {
			t.Error("WithAuthManager(non-nil) must make auth available")
		}
	})
}
