// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package tls

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"time"

	"github.com/gsoultan/gateon/internal/redis"
	"golang.org/x/crypto/acme/autocert"
)

// RedisCache implements autocert.Cache using Redis.
type RedisCache struct {
	client redis.Client
	prefix string
}

// NewRedisCache creates a new RedisCache.
func NewRedisCache(client redis.Client, prefix string) *RedisCache {
	if prefix == "" {
		prefix = "acme:"
	}
	return &RedisCache{client: client, prefix: prefix}
}

// Get reads a certificate data from Redis.
func (c *RedisCache) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := c.client.Get(ctx, c.prefix+key).Bytes()
	if err == redis.Nil {
		return nil, autocert.ErrCacheMiss
	}
	if err != nil {
		return nil, err
	}
	return val, nil
}

// Put writes a certificate data to Redis.
func (c *RedisCache) Put(ctx context.Context, key string, data []byte) error {
	return c.client.Set(ctx, c.prefix+key, data, 0).Err()
}

// Delete removes a certificate data from Redis.
func (c *RedisCache) Delete(ctx context.Context, key string) error {
	return c.client.Del(ctx, c.prefix+key).Err()
}

// SQLCache implements autocert.Cache using a SQL database.
type SQLCache struct {
	db      *sql.DB
	table   string
	dialect string
}

// NewSQLCache creates a new SQLCache.
func NewSQLCache(db *sql.DB, table, dialect string) (*SQLCache, error) {
	if table == "" {
		table = "acme_certs"
	}
	// A table name cannot be a bind parameter, so it is interpolated into every
	// statement below. That makes the identifier itself the whole trust boundary
	// for this type, and this constructor is exported — so the check belongs
	// here, once, rather than at four Sprintf sites that each have to remember.
	if !validSQLIdentifier(table) {
		return nil, fmt.Errorf("invalid table name %q: expected an unquoted SQL identifier", table)
	}
	return &SQLCache{db: db, table: table, dialect: dialect}, nil
}

// sqlIdentifierRe matches an unquoted SQL identifier: a letter or underscore
// followed by letters, digits or underscores. Deliberately narrower than what
// any one engine accepts — the point is a shape we can reason about in every
// dialect, not maximum expressiveness.
var sqlIdentifierRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)

func validSQLIdentifier(s string) bool { return sqlIdentifierRe.MatchString(s) }

// Get reads a certificate data from the database.
func (c *SQLCache) Get(ctx context.Context, key string) ([]byte, error) {
	var data []byte
	// #nosec G201 -- c.table is validated as an SQL identifier by NewSQLCache;
	// the key is a bind parameter. A table name cannot be parameterised.
	query := fmt.Sprintf("SELECT data FROM %s WHERE key = ?", c.table)
	// We might need to rebind for postgres if we were using a more complex query,
	// but here we just replace ? with $1 manually or use a helper if available.
	// Since we don't have the dialect helper here easily, let's just do it.
	if c.dialect == "postgres" {
		query = fmt.Sprintf("SELECT data FROM %s WHERE key = $1", c.table)
	}

	err := c.db.QueryRowContext(ctx, query, key).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, autocert.ErrCacheMiss
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Put writes a certificate data to the database.
func (c *SQLCache) Put(ctx context.Context, key string, data []byte) error {
	var query string
	switch c.dialect {
	case "postgres":
		query = fmt.Sprintf(`INSERT INTO %s (key, data, updated_at) VALUES ($1, $2, NOW())
			ON CONFLICT (key) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()`, c.table)
	case "mysql":
		query = fmt.Sprintf(`INSERT INTO %s (`+"`key`"+`, data) VALUES (?, ?)
			ON DUPLICATE KEY UPDATE data = VALUES(data)`, c.table)
	default: // sqlite
		query = fmt.Sprintf("INSERT OR REPLACE INTO %s (key, data, updated_at) VALUES (?, ?, ?)", c.table)
		_, err := c.db.ExecContext(ctx, query, key, data, time.Now())
		return err
	}
	_, err := c.db.ExecContext(ctx, query, key, data)
	return err
}

// Delete removes a certificate data from the database.
func (c *SQLCache) Delete(ctx context.Context, key string) error {
	// #nosec G201 -- see Get: identifier validated at construction, key bound.
	query := fmt.Sprintf("DELETE FROM %s WHERE key = ?", c.table)
	if c.dialect == "postgres" {
		query = fmt.Sprintf("DELETE FROM %s WHERE key = $1", c.table)
	}
	_, err := c.db.ExecContext(ctx, query, key)
	return err
}
