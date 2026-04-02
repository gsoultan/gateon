package db

import (
	"database/sql"
)

func init() {
	Register(1, "create_users_table", func(db *sql.DB, dialect Dialect) error {
		query := `CREATE TABLE IF NOT EXISTS users (
			id VARCHAR(255) PRIMARY KEY,
			username VARCHAR(255) UNIQUE NOT NULL,
			password TEXT NOT NULL,
			role VARCHAR(50) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`
		_, err := db.Exec(query)
		return err
	})

	Register(2, "create_path_stats_table", func(db *sql.DB, dialect Dialect) error {
		var query string
		if dialect.Driver == DriverSQLite {
			query = `CREATE TABLE IF NOT EXISTS path_stats (
				day TEXT NOT NULL,
				host TEXT NOT NULL,
				path TEXT NOT NULL,
				req_count INTEGER NOT NULL DEFAULT 0,
				latency_sum_s REAL NOT NULL DEFAULT 0,
				updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
				PRIMARY KEY(day, host, path)
			);`
		} else {
			query = `CREATE TABLE IF NOT EXISTS path_stats (
				day VARCHAR(10) NOT NULL,
				host TEXT NOT NULL,
				path TEXT NOT NULL,
				req_count BIGINT NOT NULL DEFAULT 0,
				latency_sum_s DOUBLE PRECISION NOT NULL DEFAULT 0,
				updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
				PRIMARY KEY(day, host, path)
			);`
		}
		_, err := db.Exec(query)
		return err
	})

	Register(3, "create_traces_table", func(db *sql.DB, dialect Dialect) error {
		query := `CREATE TABLE IF NOT EXISTS traces (
			id VARCHAR(255) PRIMARY KEY,
			operation_name TEXT NOT NULL,
			service_name TEXT NOT NULL,
			duration_ms BIGINT NOT NULL,
			timestamp TIMESTAMP NOT NULL,
			status VARCHAR(20) NOT NULL,
			path TEXT NOT NULL
		);`
		_, err := db.Exec(query)
		return err
	})

	Register(4, "alter_traces_duration_to_double", func(db *sql.DB, dialect Dialect) error {
		var query string
		if dialect.Driver == DriverSQLite {
			// SQLite handles type changes flexibly, but for clarity we can try to re-declare it.
			// However, ALTER COLUMN is limited in SQLite.
			// Since we want to support floats, and SQLite allows floats in BIGINT columns anyway,
			// we don't strictly NEED to change the type, but it's good practice.
			// Actually, SQLite doesn't support ALTER COLUMN TYPE.
			return nil
		} else if dialect.Driver == DriverPostgres {
			query = `ALTER TABLE traces ALTER COLUMN duration_ms TYPE DOUBLE PRECISION;`
		} else {
			// MySQL / MariaDB
			query = `ALTER TABLE traces MODIFY COLUMN duration_ms DOUBLE PRECISION NOT NULL;`
		}
		if query != "" {
			_, err := db.Exec(query)
			return err
		}
		return nil
	})
}
