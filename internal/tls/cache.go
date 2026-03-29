package tls

import (
	"context"
	"database/sql"
	"fmt"
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

// NewSQLCache creates a new SQLCache and ensures the table exists.
func NewSQLCache(db *sql.DB, table, dialect string) (*SQLCache, error) {
	if table == "" {
		table = "acme_certs"
	}
	cache := &SQLCache{db: db, table: table, dialect: dialect}
	if err := cache.init(); err != nil {
		return nil, err
	}
	return cache, nil
}

func (c *SQLCache) init() error {
	var query string
	switch c.dialect {
	case "postgres":
		query = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			key TEXT PRIMARY KEY,
			data BYTEA NOT NULL,
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		)`, c.table)
	case "mysql":
		query = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			`+"`key`"+` VARCHAR(255) PRIMARY KEY,
			data LONGBLOB NOT NULL,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		)`, c.table)
	default: // sqlite
		query = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			key TEXT PRIMARY KEY,
			data BLOB NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`, c.table)
	}
	_, err := c.db.Exec(query)
	return err
}

// Get reads a certificate data from the database.
func (c *SQLCache) Get(ctx context.Context, key string) ([]byte, error) {
	var data []byte
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
	query := fmt.Sprintf("DELETE FROM %s WHERE key = ?", c.table)
	if c.dialect == "postgres" {
		query = fmt.Sprintf("DELETE FROM %s WHERE key = $1", c.table)
	}
	_, err := c.db.ExecContext(ctx, query, key)
	return err
}
