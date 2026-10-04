// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package testutil

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"
)

// A HangDB query waits, ignoring its context, until Release, and then finds no
// row; it counts queries and the most waiting at once.
func TestHangDBWaitsUntilReleasedWhateverItsContextSays(t *testing.T) {
	h := NewHangDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for range 3 {
		wg.Go(func() {
			var s string
			errs <- h.DB.QueryRowContext(ctx, "SELECT 1").Scan(&s)
		})
	}
	for range 3 {
		select {
		case <-h.Started():
		case <-time.After(5 * time.Second):
			t.Fatal("a query never began waiting")
		}
	}
	<-ctx.Done()
	select {
	case err := <-errs:
		t.Fatalf("a query returned (%v) before Release, past its context's deadline", err)
	case <-time.After(50 * time.Millisecond):
	}
	h.Release()
	wg.Wait()
	close(errs)
	for err := range errs {
		if !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("after Release a query answered %v, want no row", err)
		}
	}
	if h.Queries() != 3 || h.Peak() != 3 {
		t.Fatalf("queries %d, peak %d; want 3 and 3", h.Queries(), h.Peak())
	}
	if _, err := h.DB.ExecContext(context.Background(), "UPDATE x"); err != nil {
		t.Fatalf("exec after Release: %v", err)
	}
}
