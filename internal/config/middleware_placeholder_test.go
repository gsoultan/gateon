// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/config/storedsecret"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestMiddlewareRegistryRefusesThePlaceholder: the file store refuses the
// placeholder in any key or value, and writes nothing -- a basic-auth user
// whose password is the placeholder is a login anyone can read in the source.
func TestMiddlewareRegistryRefusesThePlaceholder(t *testing.T) {
	for name, cfg := range map[string]map[string]string{
		"as a value":           {"type": "basic", "users": "alice:__gateon_redacted__"},
		"as an API key's name": {"type": "apikey", "key___gateon_redacted___0123456789abcdef": "tenant"},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "middlewares.json")
			reg := NewMiddlewareRegistry(path)
			mw := &gateonv1.Middleware{Id: "auth-1", Type: "auth", Config: cfg}
			if err := reg.Update(context.Background(), mw); !errors.Is(err, storedsecret.ErrPlaceholderStored) {
				t.Fatalf("Update = %v, want ErrPlaceholderStored", err)
			}
			if _, ok := reg.Get(context.Background(), "auth-1"); ok {
				t.Error("the refused middleware is in the live registry")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Errorf("middlewares.json was written for a refused middleware (stat: %v)", err)
			}
		})
	}
}
