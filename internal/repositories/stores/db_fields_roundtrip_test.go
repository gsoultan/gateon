// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package stores

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/testutil"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// fillEveryField sets every field of m, recursively, to a value that is not
// its zero value and names the field it is in, so a field the store does not
// persist comes back different and a field it swaps with another is visible.
func fillEveryField(m protoreflect.Message, depth int) {
	fields := m.Descriptor().Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		if oneof := fd.ContainingOneof(); oneof != nil && oneof.Fields().Get(0) != fd {
			continue
		}
		switch {
		case fd.IsMap():
			mp := m.Mutable(fd).Map()
			mp.Set(scalarFor(fd.MapKey(), 0).MapKey(), valueFor(mp, fd.MapValue(), depth))
		case fd.IsList():
			l := m.Mutable(fd).List()
			if fd.Kind() == protoreflect.MessageKind {
				if depth > 0 {
					el := l.NewElement()
					fillEveryField(el.Message(), depth-1)
					l.Append(el)
				}
				continue
			}
			l.Append(scalarFor(fd, 0))
			l.Append(scalarFor(fd, 1))
		case fd.Kind() == protoreflect.MessageKind:
			if depth > 0 {
				fillEveryField(m.Mutable(fd).Message(), depth-1)
			}
		default:
			m.Set(fd, scalarFor(fd, 0))
		}
	}
}

func valueFor(mp protoreflect.Map, fd protoreflect.FieldDescriptor, depth int) protoreflect.Value {
	if fd.Kind() == protoreflect.MessageKind {
		v := mp.NewValue()
		fillEveryField(v.Message(), depth-1)
		return v
	}
	return scalarFor(fd, 1)
}

func scalarFor(fd protoreflect.FieldDescriptor, n int) protoreflect.Value {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(true)
	case protoreflect.EnumKind:
		values := fd.Enum().Values()
		return protoreflect.ValueOfEnum(values.Get(min(1+n, values.Len()-1)).Number())
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32(int32(fd.Number())*10 + int32(n))
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(int64(fd.Number())*10 + int64(n))
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(uint32(fd.Number())*10 + uint32(n))
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(uint64(fd.Number())*10 + uint64(n))
	case protoreflect.FloatKind:
		return protoreflect.ValueOfFloat32(float32(fd.Number()) + 0.5)
	case protoreflect.DoubleKind:
		return protoreflect.ValueOfFloat64(float64(fd.Number()) + 0.5)
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes([]byte(fmt.Sprintf("\x00bytes-%s-%d\xff", fd.Name(), n)))
	default:
		return protoreflect.ValueOfString(fmt.Sprintf("%s-%d", fd.Name(), n))
	}
}

// storedRecord is one kind of configuration record and the database store
// that keeps it.
type storedRecord struct {
	name  string
	msg   proto.Message
	id    func(proto.Message) string
	write func(*sql.DB, db.Dialect, proto.Message) error
	read  func(*sql.DB, db.Dialect, string) (proto.Message, bool)
}

func storedRecords() []storedRecord {
	ctx := context.Background()
	return []storedRecord{
		{
			name: "route", msg: &gateonv1.Route{},
			id: func(m proto.Message) string { return m.(*gateonv1.Route).Id },
			write: func(d *sql.DB, dl db.Dialect, m proto.Message) error {
				return NewDBRouteRegistry(d, dl).Update(ctx, m.(*gateonv1.Route))
			},
			read: func(d *sql.DB, dl db.Dialect, id string) (proto.Message, bool) {
				return NewDBRouteRegistry(d, dl).Get(ctx, id)
			},
		},
		{
			name: "service", msg: &gateonv1.Service{},
			id: func(m proto.Message) string { return m.(*gateonv1.Service).Id },
			write: func(d *sql.DB, dl db.Dialect, m proto.Message) error {
				return NewDBServiceRegistry(d, dl).Update(ctx, m.(*gateonv1.Service))
			},
			read: func(d *sql.DB, dl db.Dialect, id string) (proto.Message, bool) {
				return NewDBServiceRegistry(d, dl).Get(ctx, id)
			},
		},
		{
			name: "entrypoint", msg: &gateonv1.EntryPoint{},
			id: func(m proto.Message) string { return m.(*gateonv1.EntryPoint).Id },
			write: func(d *sql.DB, dl db.Dialect, m proto.Message) error {
				return NewDBEntryPointRegistry(d, dl).Update(ctx, m.(*gateonv1.EntryPoint))
			},
			read: func(d *sql.DB, dl db.Dialect, id string) (proto.Message, bool) {
				return NewDBEntryPointRegistry(d, dl).Get(ctx, id)
			},
		},
		{
			name: "middleware", msg: &gateonv1.Middleware{},
			id: func(m proto.Message) string { return m.(*gateonv1.Middleware).Id },
			write: func(d *sql.DB, dl db.Dialect, m proto.Message) error {
				return NewDBMiddlewareRegistry(d, dl).Update(ctx, m.(*gateonv1.Middleware))
			},
			read: func(d *sql.DB, dl db.Dialect, id string) (proto.Message, bool) {
				return NewDBMiddlewareRegistry(d, dl).Get(ctx, id)
			},
		},
		{
			name: "tls option", msg: &gateonv1.TLSOption{},
			id: func(m proto.Message) string { return m.(*gateonv1.TLSOption).Id },
			write: func(d *sql.DB, dl db.Dialect, m proto.Message) error {
				return NewDBTLSOptionRegistry(d, dl).Update(ctx, m.(*gateonv1.TLSOption))
			},
			read: func(d *sql.DB, dl db.Dialect, id string) (proto.Message, bool) {
				return NewDBTLSOptionRegistry(d, dl).Get(ctx, id)
			},
		},
	}
}

// TestEveryConfigFieldSurvivesARestart writes each kind of configuration record
// with every field set and reads it back through a fresh registry, which is
// what a restart does. Once setup has run, every configuration store is one of
// these, so a field with no column is a setting the dashboard saves, the
// gateway uses until it restarts, and then silently forgets. The hand-written
// round-trip tests checked the fields someone thought of; services' health
// thresholds and a WASM middleware's module were not among them.
func TestEveryConfigFieldSurvivesARestart(t *testing.T) {
	database, dialect := newTestDB(t)
	assertEveryFieldSurvives(t, database, dialect)
}

// TestEveryConfigFieldSurvivesARestartOnPostgres is the same check against the
// other engine the stores support, whose column types -- BYTEA for a WASM
// module -- are not SQLite's. It migrates a schema of its own from nothing: in
// the shared test database the migrations have already run, so a wrong column
// type in one would never be exercised.
func TestEveryConfigFieldSurvivesARestartOnPostgres(t *testing.T) {
	dsn := freshPostgresSchema(t, testutil.PostgresDSN(t, "skipping the Postgres run"))
	database, dialect, err := db.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := db.Migrate(database, dialect); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	assertEveryFieldSurvives(t, database, dialect)
}

// freshPostgresSchema creates an empty schema, dropped when t ends, and returns
// dsn with its search_path pointed there.
func freshPostgresSchema(t *testing.T, dsn string) string {
	t.Helper()
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	schema := fmt.Sprintf("stores_roundtrip_%d", time.Now().UnixNano())
	if _, err := admin.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec("DROP SCHEMA " + schema + " CASCADE")
		_ = admin.Close()
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse DSN: %v", err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}

func assertEveryFieldSurvives(t *testing.T, database *sql.DB, dialect db.Dialect) {
	for _, rec := range storedRecords() {
		t.Run(rec.name, func(t *testing.T) {
			want := rec.msg.ProtoReflect().New().Interface()
			fillEveryField(want.ProtoReflect(), 2)
			// A record with the same ID first, so the full one goes through the
			// store's update path -- on Postgres, an ON CONFLICT clause that
			// must name every column -- and not only its insert.
			blank := rec.msg.ProtoReflect().New()
			idField := blank.Descriptor().Fields().ByName("id")
			blank.Set(idField, want.ProtoReflect().Get(idField))
			if err := rec.write(database, dialect, blank.Interface()); err != nil {
				t.Fatalf("write blank: %v", err)
			}
			if err := rec.write(database, dialect, proto.Clone(want)); err != nil {
				t.Fatalf("write: %v", err)
			}
			got, ok := rec.read(database, dialect, rec.id(want))
			if !ok {
				t.Fatal("record did not survive the restart")
			}
			for _, name := range differingFields(want.ProtoReflect(), got.ProtoReflect()) {
				t.Errorf("field %s was lost or changed across a restart", name)
			}
		})
	}
}

// differingFields names the top-level fields whose values differ.
func differingFields(want, got protoreflect.Message) []string {
	var names []string
	fields := want.Descriptor().Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		if want.Has(fd) != got.Has(fd) || !want.Get(fd).Equal(got.Get(fd)) {
			names = append(names, string(fd.Name()))
		}
	}
	return names
}
