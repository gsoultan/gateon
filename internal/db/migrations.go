package db

import (
	"database/sql"
	"strings"
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
				bytes_total INTEGER NOT NULL DEFAULT 0,
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
				bytes_total BIGINT NOT NULL DEFAULT 0,
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

	Register(5, "add_index_to_traces_timestamp", func(db *sql.DB, dialect Dialect) error {
		query := `CREATE INDEX IF NOT EXISTS idx_traces_timestamp ON traces(timestamp);`
		_, err := db.Exec(query)
		return err
	})

	Register(6, "create_acme_certs_table", func(db *sql.DB, dialect Dialect) error {
		var query string
		switch dialect.Driver {
		case DriverPostgres:
			query = `CREATE TABLE IF NOT EXISTS acme_certs (
				key TEXT PRIMARY KEY,
				data BYTEA NOT NULL,
				updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
			)`
		case DriverMySQL:
			query = `CREATE TABLE IF NOT EXISTS acme_certs (
				` + "`key`" + ` VARCHAR(255) PRIMARY KEY,
				data LONGBLOB NOT NULL,
				updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
			)`
		default: // sqlite
			query = `CREATE TABLE IF NOT EXISTS acme_certs (
				key TEXT PRIMARY KEY,
				data BLOB NOT NULL,
				updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
			)`
		}
		_, err := db.Exec(query)
		return err
	})

	Register(7, "add_missing_indexes", func(db *sql.DB, dialect Dialect) error {
		indexes := []string{
			`CREATE INDEX IF NOT EXISTS idx_traces_service_name ON traces(service_name);`,
			`CREATE INDEX IF NOT EXISTS idx_traces_status ON traces(status);`,
			`CREATE INDEX IF NOT EXISTS idx_traces_path ON traces(path);`,
			`CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);`,
		}
		for _, q := range indexes {
			if _, err := db.Exec(q); err != nil {
				return err
			}
		}
		return nil
	})

	Register(8, "add_path_stats_bytes_total", func(db *sql.DB, dialect Dialect) error {
		var query string
		switch dialect.Driver {
		case DriverPostgres:
			query = `ALTER TABLE path_stats ADD COLUMN IF NOT EXISTS bytes_total BIGINT NOT NULL DEFAULT 0;`
		case DriverMySQL:
			query = `ALTER TABLE path_stats ADD COLUMN IF NOT EXISTS bytes_total BIGINT NOT NULL DEFAULT 0;`
		default:
			query = `ALTER TABLE path_stats ADD COLUMN bytes_total INTEGER NOT NULL DEFAULT 0;`
		}

		if _, err := db.Exec(query); err != nil {
			if dialect.Driver == DriverSQLite && strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
				return nil
			}
			return err
		}
		return nil
	})

	Register(9, "create_domain_stats_table", func(db *sql.DB, dialect Dialect) error {
		var query string
		if dialect.Driver == DriverSQLite {
			query = `CREATE TABLE IF NOT EXISTS domain_stats (
				day TEXT NOT NULL,
				hour INTEGER NOT NULL,
				domain TEXT NOT NULL,
				req_count INTEGER NOT NULL DEFAULT 0,
				latency_sum_s REAL NOT NULL DEFAULT 0,
				bytes_total INTEGER NOT NULL DEFAULT 0,
				updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
				PRIMARY KEY(day, hour, domain)
			);`
		} else {
			query = `CREATE TABLE IF NOT EXISTS domain_stats (
				day VARCHAR(10) NOT NULL,
				hour INTEGER NOT NULL,
				domain VARCHAR(255) NOT NULL,
				req_count BIGINT NOT NULL DEFAULT 0,
				latency_sum_s DOUBLE PRECISION NOT NULL DEFAULT 0,
				bytes_total BIGINT NOT NULL DEFAULT 0,
				updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
				PRIMARY KEY(day, hour, domain)
			);`
		}
		_, err := db.Exec(query)
		return err
	})

	Register(10, "add_source_ip_to_traces", func(db *sql.DB, dialect Dialect) error {
		var query string
		switch dialect.Driver {
		case DriverPostgres:
			query = `ALTER TABLE traces ADD COLUMN IF NOT EXISTS source_ip TEXT NOT NULL DEFAULT '';`
		case DriverMySQL:
			query = `ALTER TABLE traces ADD COLUMN IF NOT EXISTS source_ip TEXT NOT NULL DEFAULT '';`
		default:
			query = `ALTER TABLE traces ADD COLUMN source_ip TEXT NOT NULL DEFAULT '';`
		}

		if _, err := db.Exec(query); err != nil {
			if dialect.Driver == DriverSQLite && strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
				return nil
			}
			return err
		}
		return nil
	})
}
