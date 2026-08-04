// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package db

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"github.com/gsoultan/gateon/internal/logger"
)

// Migration represents a single database migration.
type Migration struct {
	ID   int
	Name string
	Up   func(*sql.DB, Dialect) error
}

var migrations []Migration

// Register registers a new migration.
func Register(id int, name string, up func(*sql.DB, Dialect) error) {
	migrations = append(migrations, Migration{ID: id, Name: name, Up: up})
}

// Migrate runs all pending migrations.
func Migrate(db *sql.DB, dialect Dialect) error {
	if err := ensureMigrationsTable(db, dialect); err != nil {
		return fmt.Errorf("ensure migrations table: %w", err)
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].ID < migrations[j].ID
	})

	for _, m := range migrations {
		if applied, err := isApplied(db, dialect, m.ID); err != nil {
			return fmt.Errorf("check migration %d: %w", m.ID, err)
		} else if applied {
			continue
		}

		if err := m.Up(db, dialect); err != nil {
			return fmt.Errorf("migration %d (%s) failed: %w", m.ID, m.Name, err)
		}

		if err := markApplied(db, dialect, m.ID, m.Name); err != nil {
			return fmt.Errorf("mark migration %d as applied: %w", m.ID, err)
		}
	}

	return nil
}

func ensureMigrationsTable(db *sql.DB, dialect Dialect) error {
	var query string
	switch dialect.Driver {
	case DriverPostgres:
		// Check if table exists and has correct id type.
		// We filter by current_schema() to avoid matching tables in other schemas.
		var dataType string
		err := db.QueryRow("SELECT data_type FROM information_schema.columns WHERE table_name = 'migrations' AND column_name = 'id' AND table_schema = current_schema()").Scan(&dataType)
		if err == nil && strings.ToLower(dataType) != "integer" {
			// Try to fix it. We use USING id::integer to convert existing data if possible.
			if _, err := db.Exec("ALTER TABLE migrations ALTER COLUMN id TYPE INTEGER USING id::integer"); err != nil {
				// Log the error but continue; the subsequent CREATE TABLE IF NOT EXISTS might still be useful,
				// though the migrations will likely fail if the column type is still wrong.
				logger.L.LogError("failed to fix migrations table id type", "error", err, "current_type", dataType)
			}
		}

		query = `CREATE TABLE IF NOT EXISTS migrations (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		)`
	case DriverMySQL:
		query = `CREATE TABLE IF NOT EXISTS migrations (
			id INTEGER PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`
	default: // sqlite
		query = `CREATE TABLE IF NOT EXISTS migrations (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`
	}
	_, err := db.Exec(query)
	return err
}

func isApplied(db *sql.DB, dialect Dialect, id int) (bool, error) {
	query := dialect.Rebind("SELECT 1 FROM migrations WHERE id = ?")
	rows, err := db.Query(query, id)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	return rows.Next(), nil
}

func markApplied(db *sql.DB, dialect Dialect, id int, name string) error {
	query := dialect.Rebind("INSERT INTO migrations (id, name) VALUES (?, ?)")
	_, err := db.Exec(query, id, name)
	return err
}

// TableExists returns true if the specified table exists in the database.
func TableExists(db *sql.DB, dialect Dialect, name string) bool {
	var query string
	switch dialect.Driver {
	case DriverPostgres:
		query = "SELECT 1 FROM information_schema.tables WHERE table_name = ?"
	case DriverMySQL:
		query = "SHOW TABLES LIKE ?"
	default: // sqlite
		query = "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?"
	}

	rows, err := db.Query(dialect.Rebind(query), name)
	if err != nil {
		return false
	}
	defer rows.Close()
	return rows.Next()
}
