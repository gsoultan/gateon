// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package stores

import (
	"context"
	"errors"
	"testing"

	"github.com/gsoultan/gateon/internal/config/storedsecret"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestDBMiddlewareRegistryRefusesThePlaceholder: the placeholder stands for a
// stored secret; stored as one it would be an HMAC key published in the source.
// The database store refuses it whichever path the middleware came by -- the
// API restores it first, but a seed from a file or a sync does not.
func TestDBMiddlewareRegistryRefusesThePlaceholder(t *testing.T) {
	database, dialect := newTestDB(t)
	reg := NewDBMiddlewareRegistry(database, dialect)
	mw := &gateonv1.Middleware{Id: "hmac-1", Type: "hmac",
		Config: map[string]string{"secret": "__gateon_redacted__"}}

	if err := reg.Update(context.Background(), mw); !errors.Is(err, storedsecret.ErrPlaceholderStored) {
		t.Fatalf("Update = %v, want ErrPlaceholderStored", err)
	}
	if _, ok := reg.Get(context.Background(), "hmac-1"); ok {
		t.Error("the refused middleware is in the live registry")
	}
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM middlewares WHERE id = 'hmac-1'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("rows for the refused middleware = %d (%v), want 0", n, err)
	}
}
