package db

import (
	"database/sql"
	"fmt"
	"sort"
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
	var count int
	query := dialect.Rebind("SELECT COUNT(*) FROM migrations WHERE id = ?")
	err := db.QueryRow(query, id).Scan(&count)
	return count > 0, err
}

func markApplied(db *sql.DB, dialect Dialect, id int, name string) error {
	query := dialect.Rebind("INSERT INTO migrations (id, name) VALUES (?, ?)")
	_, err := db.Exec(query, id, name)
	return err
}
