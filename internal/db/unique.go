// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"errors"

	"github.com/lib/pq"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// postgresUniqueViolation is Postgres's SQLSTATE for a duplicate key.
const postgresUniqueViolation = "23505"

// IsUniqueViolation reports whether err is the database refusing a write that
// would duplicate a unique column or a primary key: SQLite's
// SQLITE_CONSTRAINT_UNIQUE or SQLITE_CONSTRAINT_PRIMARYKEY, Postgres's 23505.
//
// A store that means "create, and refuse a duplicate" lets the constraint
// decide rather than looking first -- two concurrent writes can both pass a
// lookup, and only one can pass the constraint -- and this is how it tells that
// refusal from a failure. Other constraint failures (NOT NULL, CHECK, foreign
// keys) are not duplicates and are not reported as one.
func IsUniqueViolation(err error) bool {
	if pqErr, ok := errors.AsType[*pq.Error](err); ok {
		return pqErr.Code == postgresUniqueViolation
	}
	if liteErr, ok := errors.AsType[*sqlite.Error](err); ok {
		switch liteErr.Code() {
		case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
			return true
		}
	}
	return false
}
