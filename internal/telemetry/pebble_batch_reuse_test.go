// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"fmt"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
)

// openMemPebble gives each benchmark its own in-memory store, so nothing
// touches the checkout and the numbers are not a disk measurement.
func openMemPebble(b *testing.B) *pebble.DB {
	b.Helper()
	db, err := pebble.Open("bench", &pebble.Options{FS: vfs.NewMem()})
	if err != nil {
		b.Fatalf("open pebble: %v", err)
	}
	b.Cleanup(func() { _ = db.Close() })
	return db
}

// The two benchmarks below measure the difference the fix makes, rather than
// asserting it from the library's source. Pebble hands batches out from a
// sync.Pool and only Batch.Close returns one; Commit does not. A flush that
// commits and walks away therefore throws away the batch's data buffer -- which
// has grown to hold every record in the flush -- and takes a fresh allocation
// next time.
//
//	go test -run '^$' -bench 'PebbleBatch' -benchmem ./internal/telemetry/

// Deliberately small. CI runs this package's benchmarks at -benchtime 50000x,
// and the unclosed variant allocates a whole batch buffer per iteration -- at a
// realistic 1024-record flush that would be tens of gigabytes of churn on a
// shared runner for a number this already establishes. The ratio is what
// matters and it holds at any size; the absolute effect scales with the batch.
const benchRecordsPerBatch = 32

func benchBatchPayload() ([]byte, []byte) {
	// Roughly the shape of a marshalled TraceRecord: a short key, a value with
	// headers and a body in it.
	return []byte("trace/2026-09-23T00:00:00Z/0123456789abcdef"),
		[]byte(fmt.Sprintf("%0*d", 256, 1))
}

func BenchmarkPebbleBatchClosedAfterCommit(b *testing.B) {
	db := openMemPebble(b)
	key, val := benchBatchPayload()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		batch := db.NewBatch()
		for i := range benchRecordsPerBatch {
			_ = batch.Set(append(key, byte(i)), val, pebble.NoSync)
		}
		if err := batch.Commit(pebble.NoSync); err != nil {
			b.Fatalf("commit: %v", err)
		}
		_ = batch.Close()
	}
}

func BenchmarkPebbleBatchLeftUnclosed(b *testing.B) {
	db := openMemPebble(b)
	key, val := benchBatchPayload()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		batch := db.NewBatch()
		for i := range benchRecordsPerBatch {
			_ = batch.Set(append(key, byte(i)), val, pebble.NoSync)
		}
		if err := batch.Commit(pebble.NoSync); err != nil {
			b.Fatalf("commit: %v", err)
		}
		// No Close: the batch never goes back to Pebble's pool.
	}
}
