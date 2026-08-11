// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package stores

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/db"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type DBMiddlewareRegistry struct {
	*config.MiddlewareRegistry
	db      *sql.DB
	dialect db.Dialect
}

func NewDBMiddlewareRegistry(database *sql.DB, dialect db.Dialect) *DBMiddlewareRegistry {
	r := &DBMiddlewareRegistry{
		MiddlewareRegistry: config.NewEmptyMiddlewareRegistry(),
		db:                 database,
		dialect:            dialect,
	}
	r.loadFromDB()
	return r
}

func (r *DBMiddlewareRegistry) loadFromDB() {
	r.Mu().Lock()
	defer r.Mu().Unlock()

	query := "SELECT id, name, type, config FROM middlewares"
	rows, err := r.db.Query(query)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var m gateonv1.Middleware
		var configStr string
		if err := rows.Scan(&m.Id, &m.Name, &m.Type, &configStr); err != nil {
			continue
		}
		if configStr != "" {
			var cfg map[string]string
			if err := json.Unmarshal([]byte(configStr), &cfg); err == nil {
				m.Config = cfg
			}
		}
		r.Middlewares()[m.Id] = &m
	}
}

func (r *DBMiddlewareRegistry) Update(ctx context.Context, m *gateonv1.Middleware) error {
	r.Mu().Lock()
	defer r.Mu().Unlock()

	configStr := ""
	if m.Config != nil {
		if b, err := json.Marshal(m.Config); err == nil {
			configStr = string(b)
		}
	}

	var query string
	if r.dialect.Driver == db.DriverPostgres {
		query = `INSERT INTO middlewares (id, name, type, config, updated_at)
			VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
			ON CONFLICT (id) DO UPDATE SET
				name = EXCLUDED.name,
				type = EXCLUDED.type,
				config = EXCLUDED.config,
				updated_at = CURRENT_TIMESTAMP`
	} else {
		query = `REPLACE INTO middlewares (id, name, type, config, updated_at)
			VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`
	}

	_, err := r.db.Exec(r.dialect.Rebind(query), m.Id, m.Name, m.Type, configStr)
	if err != nil {
		return err
	}

	r.Middlewares()[m.Id] = m
	return nil
}

func (r *DBMiddlewareRegistry) Delete(ctx context.Context, id string) error {
	r.Mu().Lock()
	defer r.Mu().Unlock()

	query := r.dialect.Rebind("DELETE FROM middlewares WHERE id = ?")
	if _, err := r.db.Exec(query, id); err != nil {
		return err
	}

	delete(r.Middlewares(), id)
	return nil
}
