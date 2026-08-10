// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package stores

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/db"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type DBRouteRegistry struct {
	*config.RouteRegistry
	db      *sql.DB
	dialect db.Dialect
}

func NewDBRouteRegistry(database *sql.DB, dialect db.Dialect) *DBRouteRegistry {
	r := &DBRouteRegistry{
		RouteRegistry: config.NewEmptyRouteRegistry(),
		db:            database,
		dialect:       dialect,
	}
	r.loadFromDB()
	return r
}

func (r *DBRouteRegistry) loadFromDB() {
	r.Mu().Lock()
	defer r.Mu().Unlock()

	query := "SELECT id, name, type, entrypoints, rule, priority, middlewares, service_id, tls_config, disabled FROM routes"
	rows, err := r.db.Query(query)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var rt gateonv1.Route
		var entrypoints, middlewares, tlsConfig string
		if err := rows.Scan(&rt.Id, &rt.Name, &rt.Type, &entrypoints, &rt.Rule, &rt.Priority, &middlewares, &rt.ServiceId, &tlsConfig, &rt.Disabled); err != nil {
			continue
		}
		if entrypoints != "" {
			rt.Entrypoints = strings.Split(entrypoints, ",")
		}
		if middlewares != "" {
			rt.Middlewares = strings.Split(middlewares, ",")
		}
		if tlsConfig != "" {
			var tls gateonv1.RouteTLSConfig
			if err := json.Unmarshal([]byte(tlsConfig), &tls); err == nil {
				rt.Tls = &tls
			}
		}
		r.Routes()[rt.Id] = &rt
	}
	r.RebuildSortedLocked()
}

func (r *DBRouteRegistry) Update(ctx context.Context, rt *gateonv1.Route) error {
	r.Mu().Lock()
	defer r.Mu().Unlock()

	entrypoints := strings.Join(rt.Entrypoints, ",")
	middlewares := strings.Join(rt.Middlewares, ",")
	tlsConfig := ""
	if rt.Tls != nil {
		if b, err := json.Marshal(rt.Tls); err == nil {
			tlsConfig = string(b)
		}
	}

	var query string
	if r.dialect.Driver == db.DriverPostgres {
		query = `INSERT INTO routes (id, name, type, entrypoints, rule, priority, middlewares, service_id, tls_config, disabled, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
			ON CONFLICT (id) DO UPDATE SET
				name = EXCLUDED.name,
				type = EXCLUDED.type,
				entrypoints = EXCLUDED.entrypoints,
				rule = EXCLUDED.rule,
				priority = EXCLUDED.priority,
				middlewares = EXCLUDED.middlewares,
				service_id = EXCLUDED.service_id,
				tls_config = EXCLUDED.tls_config,
				disabled = EXCLUDED.disabled,
				updated_at = CURRENT_TIMESTAMP`
	} else {
		// SQLite / MySQL
		query = `REPLACE INTO routes (id, name, type, entrypoints, rule, priority, middlewares, service_id, tls_config, disabled, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`
	}

	_, err := r.db.Exec(r.dialect.Rebind(query), rt.Id, rt.Name, rt.Type, entrypoints, rt.Rule, rt.Priority, middlewares, rt.ServiceId, tlsConfig, rt.Disabled)
	if err != nil {
		return err
	}

	r.Routes()[rt.Id] = rt
	r.RebuildSortedLocked()
	return nil
}

func (r *DBRouteRegistry) Delete(ctx context.Context, id string) error {
	r.Mu().Lock()
	defer r.Mu().Unlock()

	query := r.dialect.Rebind("DELETE FROM routes WHERE id = ?")
	if _, err := r.db.Exec(query, id); err != nil {
		return err
	}

	delete(r.Routes(), id)
	r.RebuildSortedLocked()
	return nil
}
