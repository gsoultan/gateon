// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package stores

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/db"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type DBEntryPointRegistry struct {
	*config.EntryPointRegistry
	db      *sql.DB
	dialect db.Dialect
}

func NewDBEntryPointRegistry(database *sql.DB, dialect db.Dialect) *DBEntryPointRegistry {
	r := &DBEntryPointRegistry{
		EntryPointRegistry: config.NewEmptyEntryPointRegistry(),
		db:                 database,
		dialect:            dialect,
	}
	r.loadFromDB()
	return r
}

func (r *DBEntryPointRegistry) loadFromDB() {
	r.Mu().Lock()
	defer r.Mu().Unlock()

	query := "SELECT id, name, address, type, protocol, protocols, tls_config, read_timeout_ms, write_timeout_ms, max_connections, access_log_enabled FROM entrypoints"
	rows, err := r.db.Query(query)
	if err != nil {
		return
	}
	defer rows.Close()

	newMap := make(map[string]*gateonv1.EntryPoint)
	for rows.Next() {
		var ep gateonv1.EntryPoint
		var typeVal, protocolVal int32
		var protocolsStr, tlsStr string
		if err := rows.Scan(&ep.Id, &ep.Name, &ep.Address, &typeVal, &protocolVal, &protocolsStr, &tlsStr, &ep.ReadTimeoutMs, &ep.WriteTimeoutMs, &ep.MaxConnections, &ep.AccessLogEnabled); err != nil {
			continue
		}
		ep.Type = gateonv1.EntryPoint_Type(typeVal)
		ep.Protocol = gateonv1.EntryPoint_Protocol(protocolVal)
		if protocolsStr != "" {
			for _, p := range strings.Split(protocolsStr, ",") {
				if pi, err := strconv.Atoi(p); err == nil {
					ep.Protocols = append(ep.Protocols, gateonv1.EntryPoint_Protocol(pi))
				}
			}
		}
		if tlsStr != "" {
			var cfg gateonv1.TlsConfig
			if err := json.Unmarshal([]byte(tlsStr), &cfg); err == nil {
				ep.Tls = &cfg
			}
		}
		newMap[ep.Id] = &ep
	}
	r.EntryPoints().Store(&newMap)
}

func (r *DBEntryPointRegistry) Update(ctx context.Context, ep *gateonv1.EntryPoint) error {
	r.Mu().Lock()
	defer r.Mu().Unlock()

	var protocols []string
	for _, p := range ep.Protocols {
		protocols = append(protocols, strconv.Itoa(int(p)))
	}
	protocolsStr := strings.Join(protocols, ",")

	tlsStr := ""
	if ep.Tls != nil {
		if b, err := json.Marshal(ep.Tls); err == nil {
			tlsStr = string(b)
		}
	}

	var query string
	if r.dialect.Driver == db.DriverPostgres {
		query = `INSERT INTO entrypoints (id, name, address, type, protocol, protocols, tls_config, read_timeout_ms, write_timeout_ms, max_connections, access_log_enabled, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
			ON CONFLICT (id) DO UPDATE SET
				name = EXCLUDED.name,
				address = EXCLUDED.address,
				type = EXCLUDED.type,
				protocol = EXCLUDED.protocol,
				protocols = EXCLUDED.protocols,
				tls_config = EXCLUDED.tls_config,
				read_timeout_ms = EXCLUDED.read_timeout_ms,
				write_timeout_ms = EXCLUDED.write_timeout_ms,
				max_connections = EXCLUDED.max_connections,
				access_log_enabled = EXCLUDED.access_log_enabled,
				updated_at = CURRENT_TIMESTAMP`
	} else {
		query = `REPLACE INTO entrypoints (id, name, address, type, protocol, protocols, tls_config, read_timeout_ms, write_timeout_ms, max_connections, access_log_enabled, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`
	}

	_, err := r.db.Exec(r.dialect.Rebind(query), ep.Id, ep.Name, ep.Address, int32(ep.Type), int32(ep.Protocol), protocolsStr, tlsStr, ep.ReadTimeoutMs, ep.WriteTimeoutMs, ep.MaxConnections, ep.AccessLogEnabled)
	if err != nil {
		return err
	}

	mPtr := r.EntryPoints().Load()
	newMap := make(map[string]*gateonv1.EntryPoint)
	if mPtr != nil {
		for k, v := range *mPtr {
			newMap[k] = v
		}
	}
	newMap[ep.Id] = ep
	r.EntryPoints().Store(&newMap)
	return nil
}

func (r *DBEntryPointRegistry) Delete(ctx context.Context, id string) error {
	r.Mu().Lock()
	defer r.Mu().Unlock()

	query := r.dialect.Rebind("DELETE FROM entrypoints WHERE id = ?")
	if _, err := r.db.Exec(query, id); err != nil {
		return err
	}

	mPtr := r.EntryPoints().Load()
	if mPtr == nil {
		return nil
	}
	newMap := make(map[string]*gateonv1.EntryPoint)
	for k, v := range *mPtr {
		newMap[k] = v
	}
	delete(newMap, id)
	r.EntryPoints().Store(&newMap)
	return nil
}
