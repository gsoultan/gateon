// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package testutil

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
)

// HangDB is a database whose every query waits until Release and ignores its
// context while it waits: lib/pq against a Postgres that has stopped
// answering -- frozen, partitioned, or behind a lock -- which on a cancelled
// context asks the server to cancel and goes on waiting for an answer that
// never comes. After Release every query, waiting or new, finds no row.
//
// It counts the queries it was asked and the most that were waiting at once,
// which is what a test of a lookup's bounds needs to read.
type HangDB struct {
	DB       *sql.DB
	release  chan struct{}
	once     sync.Once
	queries  atomic.Int64
	inFlight atomic.Int64
	peak     atomic.Int64
	// started receives one value per query that began waiting, without
	// blocking the query when nobody reads it.
	started chan struct{}
}

// NewHangDB returns a HangDB that is released, and closed, when t ends.
func NewHangDB(t testing.TB) *HangDB {
	t.Helper()
	h := &HangDB{release: make(chan struct{}), started: make(chan struct{}, 1024)}
	h.DB = sql.OpenDB(hangConnector{h: h})
	t.Cleanup(func() {
		h.Release()
		_ = h.DB.Close()
	})
	return h
}

// Release ends every wait, and every later query answers at once.
func (h *HangDB) Release() { h.once.Do(func() { close(h.release) }) }

// Queries reports how many queries were asked.
func (h *HangDB) Queries() int64 { return h.queries.Load() }

// Peak reports the most queries that were waiting at once.
func (h *HangDB) Peak() int64 { return h.peak.Load() }

// Started receives once per query that began waiting (up to 1024 unread).
func (h *HangDB) Started() <-chan struct{} { return h.started }

func (h *HangDB) query() {
	h.queries.Add(1)
	n := h.inFlight.Add(1)
	defer h.inFlight.Add(-1)
	for {
		p := h.peak.Load()
		if n <= p || h.peak.CompareAndSwap(p, n) {
			break
		}
	}
	select {
	case h.started <- struct{}{}:
	default:
	}
	<-h.release
}

type hangConnector struct{ h *HangDB }

func (c hangConnector) Connect(context.Context) (driver.Conn, error) { return hangConn(c), nil }
func (c hangConnector) Driver() driver.Driver                        { return hangDriver{} }

type hangDriver struct{}

func (hangDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("hangdb: open through the connector")
}

type hangConn struct{ h *HangDB }

func (c hangConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	c.h.query()
	return noRows{}, nil
}

func (c hangConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.h.query()
	return driver.RowsAffected(0), nil
}

func (hangConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("hangdb: no prepared statements")
}
func (hangConn) Close() error              { return nil }
func (hangConn) Begin() (driver.Tx, error) { return nil, errors.New("hangdb: no transactions") }

type noRows struct{}

func (noRows) Columns() []string         { return nil }
func (noRows) Close() error              { return nil }
func (noRows) Next([]driver.Value) error { return io.EOF }
