// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package stores

import (
	"context"
	"database/sql"
	"encoding/json"
	"maps"
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

// loadFromDB fills the registry at construction. A failure is logged by
// reload and leaves the registry as it was: empty.
func (r *DBRouteRegistry) loadFromDB() { _ = r.reload(context.Background()) }

// Reload replaces what the registry holds with what the database holds now:
// how a peer takes a change another gateway wrote (ADR 0081). A read that
// fails changes nothing and is returned.
func (r *DBRouteRegistry) Reload(ctx context.Context) error { return r.reload(ctx) }

func (r *DBRouteRegistry) reload(ctx context.Context) error {
	r.Mu().Lock()
	defer r.Mu().Unlock()

	query := "SELECT id, name, type, entrypoints, rule, priority, middlewares, service_id, tls_config, disabled, stream_mode FROM routes"
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		logLoadQueryFailed("routes", err)
		return err
	}
	defer rows.Close()

	// Collected first and stored only once every row is read: a read that
	// fails part way must not replace what the gateway is serving with the
	// part of it that arrived.
	fresh := make(map[string]*gateonv1.Route)
	for rows.Next() {
		var rt gateonv1.Route
		var entrypoints, middlewares, tlsConfig string
		var streamMode int32
		if err := rows.Scan(&rt.Id, &rt.Name, &rt.Type, &entrypoints, &rt.Rule, &rt.Priority, &middlewares, &rt.ServiceId, &tlsConfig, &rt.Disabled, &streamMode); err != nil {
			logRecordDropped("route", "", "", err)
			continue
		}
		rt.StreamMode = gateonv1.Route_StreamMode(streamMode)
		if entrypoints != "" {
			rt.Entrypoints = strings.Split(entrypoints, ",")
		}
		if middlewares != "" {
			rt.Middlewares = strings.Split(middlewares, ",")
		}
		if tlsConfig != "" {
			var tls gateonv1.RouteTLSConfig
			if err := json.Unmarshal([]byte(tlsConfig), &tls); err != nil {
				logRecordDropped("route", rt.Id, "tls_config", err)
				continue
			}
			rt.Tls = &tls
		}
		fresh[rt.Id] = &rt
	}
	if err := rows.Err(); err != nil {
		logLoadTruncated("routes", err)
		return err
	}
	clear(r.Routes())
	maps.Copy(r.Routes(), fresh)
	r.RebuildSortedLocked()
	return nil
}

func (r *DBRouteRegistry) Update(ctx context.Context, rt *gateonv1.Route) error {
	r.Mu().Lock()
	defer r.Mu().Unlock()

	// Validated before anything is written: a comma in one of these names would
	// be split back into two on load. See list_column.go.
	entrypoints, err := joinListColumn("entrypoint name", rt.Entrypoints)
	if err != nil {
		return err
	}
	middlewares, err := joinListColumn("middleware name", rt.Middlewares)
	if err != nil {
		return err
	}
	tlsConfig := ""
	if rt.Tls != nil {
		if b, err := json.Marshal(rt.Tls); err == nil {
			tlsConfig = string(b)
		}
	}

	var query string
	if r.dialect.Driver == db.DriverPostgres {
		query = `INSERT INTO routes (id, name, type, entrypoints, rule, priority, middlewares, service_id, tls_config, disabled, stream_mode, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
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
				stream_mode = EXCLUDED.stream_mode,
				updated_at = CURRENT_TIMESTAMP`
	} else {
		// SQLite
		query = `REPLACE INTO routes (id, name, type, entrypoints, rule, priority, middlewares, service_id, tls_config, disabled, stream_mode, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`
	}

	if _, err := r.db.Exec(r.dialect.Rebind(query), rt.Id, rt.Name, rt.Type, entrypoints, rt.Rule, rt.Priority, middlewares, rt.ServiceId, tlsConfig, rt.Disabled, int32(rt.StreamMode)); err != nil {
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
