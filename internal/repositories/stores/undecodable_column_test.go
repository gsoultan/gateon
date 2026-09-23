// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package stores

import (
	"context"
	"database/sql"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// corrupt writes a value into one column of one row, standing in for whatever
// put it there -- a partial write, a hand-edited database, a proto field whose
// type changed under rows written by an older build.
func corrupt(t *testing.T, database *sql.DB, tbl, col, id string) {
	t.Helper()
	// Tests own this database and the identifiers are literals at the call
	// sites below, not input.
	q := "UPDATE " + tbl + " SET " + col + " = '{not json' WHERE id = ?"
	if _, err := database.Exec(q, id); err != nil {
		t.Fatalf("corrupt %s.%s: %v", tbl, col, err)
	}
}

// TestEntryPointWithUndecodableTLSIsNotServed is the one that matters most.
//
// entrypoint_http.go gates termination on `ep.Tls != nil`. The loader used to
// leave that nil when the tls_config column would not decode -- silently, with
// a non-empty tls_config still in the database saying otherwise -- so the
// listener came up serving **plaintext on a port configured for HTTPS**.
//
// Not serving the entrypoint at all is the safe direction: a port that refuses
// connections is noticed by the operator in minutes; a port serving plaintext
// is noticed by whoever is reading the traffic.
func TestEntryPointWithUndecodableTLSIsNotServed(t *testing.T) {
	database, dialect := newTestDB(t)
	ctx := context.Background()

	ep := &gateonv1.EntryPoint{
		Id:      "ep-1",
		Name:    "websecure",
		Address: ":443",
		Tls:     &gateonv1.TlsConfig{Enabled: true},
	}
	if err := NewDBEntryPointRegistry(database, dialect).Update(ctx, ep); err != nil {
		t.Fatalf("seed entrypoint: %v", err)
	}

	// Sanity: it round-trips with TLS before anything is corrupted, or the rest
	// of this test would pass for the wrong reason.
	before, ok := NewDBEntryPointRegistry(database, dialect).Get(ctx, "ep-1")
	if !ok || before.Tls == nil || !before.Tls.Enabled {
		t.Fatalf("before corruption the entrypoint should load with TLS enabled, got %+v", before)
	}

	corrupt(t, database, "entrypoints", "tls_config", "ep-1")

	got, ok := NewDBEntryPointRegistry(database, dialect).Get(ctx, "ep-1")
	if !ok || got == nil {
		return // dropped, which is the fix
	}
	if got.Tls == nil {
		t.Fatal("an entrypoint whose tls_config could not be decoded was registered " +
			"with Tls nil; entrypoint_http.go reads that as \"do not terminate TLS\", " +
			"so this port comes up plaintext")
	}
	t.Fatalf("unexpected: corrupted tls_config still decoded to %+v", got.Tls)
}

// TestMiddlewareWithUndecodableConfigIsNotRegistered: registering it with an
// empty config runs the middleware on defaults -- a WAF or a rate limit that
// an operator configured and that is silently not the one configured. Dropping
// it makes router.go refuse the routes that name it, which is fail-closed.
func TestMiddlewareWithUndecodableConfigIsNotRegistered(t *testing.T) {
	database, dialect := newTestDB(t)
	ctx := context.Background()

	mw := &gateonv1.Middleware{
		Id:     "mw-1",
		Name:   "ratelimit",
		Type:   "ratelimit",
		Config: map[string]string{"requests_per_minute": "60"},
	}
	if err := NewDBMiddlewareRegistry(database, dialect).Update(ctx, mw); err != nil {
		t.Fatalf("seed middleware: %v", err)
	}
	if got, ok := NewDBMiddlewareRegistry(database, dialect).Get(ctx, "mw-1"); !ok || got.Config["requests_per_minute"] != "60" {
		t.Fatalf("before corruption the middleware should load with its config, got %+v", got)
	}

	corrupt(t, database, "middlewares", "config", "mw-1")

	got, ok := NewDBMiddlewareRegistry(database, dialect).Get(ctx, "mw-1")
	if ok && got != nil && len(got.Config) == 0 {
		t.Fatal("a middleware whose config could not be decoded was registered with " +
			"an empty config; it runs on defaults while the database says otherwise")
	}
}

// TestServiceWithUndecodableTLSClientConfigIsNotRegistered: TlsClientConfig is
// the backend's mTLS identity. Registering the service without it means
// connecting to that backend presenting no client certificate at all -- the
// same downgrade the proxy builder refuses elsewhere, arrived at by a
// different route.
func TestServiceWithUndecodableTLSClientConfigIsNotRegistered(t *testing.T) {
	database, dialect := newTestDB(t)
	ctx := context.Background()

	svc := &gateonv1.Service{
		Id:              "svc-1",
		Name:            "api",
		TlsClientConfig: &gateonv1.TlsClientConfig{Enabled: true, CertFile: "/etc/gateon/client.crt", KeyFile: "/etc/gateon/client.key"},
	}
	if err := NewDBServiceRegistry(database, dialect).Update(ctx, svc); err != nil {
		t.Fatalf("seed service: %v", err)
	}

	corrupt(t, database, "services", "tls_client_config", "svc-1")

	got, ok := NewDBServiceRegistry(database, dialect).Get(ctx, "svc-1")
	if ok && got != nil && got.TlsClientConfig == nil {
		t.Fatal("a service whose tls_client_config could not be decoded was registered " +
			"without it; the proxy then connects to that backend presenting no " +
			"client certificate")
	}
}

// TestRegistryComesUpEmptyAndLoudWhenItsTableIsGone covers the other half of
// the same problem. A registry that cannot read its table at all used to
// return quietly, and a gateway with no routes looks exactly like a gateway
// that was never given any.
func TestRegistryComesUpEmptyAndLoudWhenItsTableIsGone(t *testing.T) {
	database, dialect := newTestDB(t)
	ctx := context.Background()

	if _, err := database.Exec("DROP TABLE routes"); err != nil {
		t.Fatalf("drop routes: %v", err)
	}

	r := NewDBRouteRegistry(database, dialect)
	if got := r.List(ctx); len(got) != 0 {
		t.Fatalf("expected an empty registry, got %d routes", len(got))
	}
}

// TestRecordThatWillNotScanIsDropped: SQLite stores what it is given, so a
// text value in a numeric column survives the write and fails at Scan. The row
// used to be skipped with no indication, which is the same invisibility as the
// decode failures above, one layer earlier.
func TestRecordThatWillNotScanIsDropped(t *testing.T) {
	database, dialect := newTestDB(t)
	ctx := context.Background()

	ep := &gateonv1.EntryPoint{Id: "ep-scan", Name: "web", Address: ":80"}
	if err := NewDBEntryPointRegistry(database, dialect).Update(ctx, ep); err != nil {
		t.Fatalf("seed entrypoint: %v", err)
	}
	if _, ok := NewDBEntryPointRegistry(database, dialect).Get(ctx, "ep-scan"); !ok {
		t.Fatal("before corruption the entrypoint should load")
	}

	if _, err := database.Exec(
		"UPDATE entrypoints SET read_timeout_ms = 'not-a-number' WHERE id = ?", "ep-scan"); err != nil {
		t.Fatalf("corrupt read_timeout_ms: %v", err)
	}

	if _, ok := NewDBEntryPointRegistry(database, dialect).Get(ctx, "ep-scan"); ok {
		t.Error("a row that cannot be scanned was still registered")
	}
}
