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

type DBServiceRegistry struct {
	*config.ServiceRegistry
	db      *sql.DB
	dialect db.Dialect
}

func NewDBServiceRegistry(database *sql.DB, dialect db.Dialect) *DBServiceRegistry {
	r := &DBServiceRegistry{
		ServiceRegistry: config.NewEmptyServiceRegistry(),
		db:              database,
		dialect:         dialect,
	}
	r.loadFromDB()
	return r
}

func (r *DBServiceRegistry) loadFromDB() {
	r.Mu().Lock()
	defer r.Mu().Unlock()

	query := "SELECT id, name, backend_type, load_balancer_policy, health_check_path, weighted_targets, discovery_url, tls_client_config, health_check_port, health_check_protocol, health_check_type, l4_health_check_interval_ms, l4_health_check_timeout_ms, l4_udp_session_timeout_s, l4_proxy_protocol FROM services"
	rows, err := r.db.Query(query)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var s gateonv1.Service
		var targetsStr, tlsStr string
		if err := rows.Scan(&s.Id, &s.Name, &s.BackendType, &s.LoadBalancerPolicy, &s.HealthCheckPath, &targetsStr, &s.DiscoveryUrl, &tlsStr, &s.HealthCheckPort, &s.HealthCheckProtocol, &s.HealthCheckType, &s.L4HealthCheckIntervalMs, &s.L4HealthCheckTimeoutMs, &s.L4UdpSessionTimeoutS, &s.L4ProxyProtocol); err != nil {
			continue
		}
		if targetsStr != "" {
			_ = json.Unmarshal([]byte(targetsStr), &s.WeightedTargets)
		}
		if tlsStr != "" {
			var tlsCfg gateonv1.TlsClientConfig
			if err := json.Unmarshal([]byte(tlsStr), &tlsCfg); err == nil {
				s.TlsClientConfig = &tlsCfg
			}
		}

		r.Services()[s.Id] = &s
	}
}

func (r *DBServiceRegistry) Update(ctx context.Context, s *gateonv1.Service) error {
	r.Mu().Lock()
	defer r.Mu().Unlock()

	targetsStr := "[]"
	if b, err := json.Marshal(s.WeightedTargets); err == nil {
		targetsStr = string(b)
	}
	tlsStr := ""
	if s.TlsClientConfig != nil {
		if b, err := json.Marshal(s.TlsClientConfig); err == nil {
			tlsStr = string(b)
		}
	}

	var query string
	if r.dialect.Driver == db.DriverPostgres {
		query = `INSERT INTO services (id, name, backend_type, load_balancer_policy, health_check_path, weighted_targets, discovery_url, tls_client_config, health_check_port, health_check_protocol, health_check_type, l4_health_check_interval_ms, l4_health_check_timeout_ms, l4_udp_session_timeout_s, l4_proxy_protocol, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
			ON CONFLICT (id) DO UPDATE SET
				name = EXCLUDED.name,
				backend_type = EXCLUDED.backend_type,
				load_balancer_policy = EXCLUDED.load_balancer_policy,
				health_check_path = EXCLUDED.health_check_path,
				weighted_targets = EXCLUDED.weighted_targets,
				discovery_url = EXCLUDED.discovery_url,
				tls_client_config = EXCLUDED.tls_client_config,
				health_check_port = EXCLUDED.health_check_port,
				health_check_protocol = EXCLUDED.health_check_protocol,
				health_check_type = EXCLUDED.health_check_type,
				l4_health_check_interval_ms = EXCLUDED.l4_health_check_interval_ms,
				l4_health_check_timeout_ms = EXCLUDED.l4_health_check_timeout_ms,
				l4_udp_session_timeout_s = EXCLUDED.l4_udp_session_timeout_s,
				l4_proxy_protocol = EXCLUDED.l4_proxy_protocol,
				updated_at = CURRENT_TIMESTAMP`
	} else {
		query = `REPLACE INTO services (id, name, backend_type, load_balancer_policy, health_check_path, weighted_targets, discovery_url, tls_client_config, health_check_port, health_check_protocol, health_check_type, l4_health_check_interval_ms, l4_health_check_timeout_ms, l4_udp_session_timeout_s, l4_proxy_protocol, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`
	}

	_, err := r.db.Exec(r.dialect.Rebind(query), s.Id, s.Name, s.BackendType, s.LoadBalancerPolicy, s.HealthCheckPath, targetsStr, s.DiscoveryUrl, tlsStr, s.HealthCheckPort, s.HealthCheckProtocol, int32(s.HealthCheckType), s.L4HealthCheckIntervalMs, s.L4HealthCheckTimeoutMs, s.L4UdpSessionTimeoutS, s.L4ProxyProtocol)
	if err != nil {
		return err
	}

	r.Services()[s.Id] = s
	return nil
}

func (r *DBServiceRegistry) Delete(ctx context.Context, id string) error {
	r.Mu().Lock()
	defer r.Mu().Unlock()

	query := r.dialect.Rebind("DELETE FROM services WHERE id = ?")
	if _, err := r.db.Exec(query, id); err != nil {
		return err
	}

	delete(r.Services(), id)
	return nil
}
