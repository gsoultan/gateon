// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package stores

import (
	"context"
	"database/sql"
	"encoding/json"
	"maps"

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

// loadFromDB fills the registry at construction. A failure is logged by
// reload and leaves the registry as it was: empty.
func (r *DBServiceRegistry) loadFromDB() { _ = r.reload(context.Background()) }

// Reload replaces what the registry holds with what the database holds now:
// how a peer takes a change another gateway wrote (ADR 0081). A read that
// fails changes nothing and is returned.
func (r *DBServiceRegistry) Reload(ctx context.Context) error { return r.reload(ctx) }

func (r *DBServiceRegistry) reload(ctx context.Context) error {
	r.Mu().Lock()
	defer r.Mu().Unlock()

	query := "SELECT id, name, backend_type, load_balancer_policy, health_check_path, weighted_targets, discovery_url, tls_client_config, health_check_port, health_check_protocol, health_check_type, l4_health_check_interval_ms, l4_health_check_timeout_ms, l4_udp_session_timeout_s, l4_proxy_protocol, unhealthy_threshold, healthy_threshold FROM services"
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		logLoadQueryFailed("services", err)
		return err
	}
	defer rows.Close()

	// Collected first and stored only once every row is read: a read that
	// fails part way must not replace what the gateway is serving with the
	// part of it that arrived.
	fresh := make(map[string]*gateonv1.Service)
	for rows.Next() {
		var s gateonv1.Service
		var targetsStr, tlsStr string
		if err := rows.Scan(&s.Id, &s.Name, &s.BackendType, &s.LoadBalancerPolicy, &s.HealthCheckPath, &targetsStr, &s.DiscoveryUrl, &tlsStr, &s.HealthCheckPort, &s.HealthCheckProtocol, &s.HealthCheckType, &s.L4HealthCheckIntervalMs, &s.L4HealthCheckTimeoutMs, &s.L4UdpSessionTimeoutS, &s.L4ProxyProtocol, &s.UnhealthyThreshold, &s.HealthyThreshold); err != nil {
			logRecordDropped("service", "", "", err)
			continue
		}
		if targetsStr != "" {
			if err := json.Unmarshal([]byte(targetsStr), &s.WeightedTargets); err != nil {
				logRecordDropped("service", s.Id, "weighted_targets", err)
				continue
			}
		}
		if tlsStr != "" {
			var tlsCfg gateonv1.TlsClientConfig
			if err := json.Unmarshal([]byte(tlsStr), &tlsCfg); err != nil {
				// The backend's mTLS identity. Registering the service without
				// it means connecting to that backend presenting no client
				// certificate at all.
				logRecordDropped("service", s.Id, "tls_client_config", err)
				continue
			}
			s.TlsClientConfig = &tlsCfg
		}

		fresh[s.Id] = &s
	}
	if err := rows.Err(); err != nil {
		logLoadTruncated("services", err)
		return err
	}
	clear(r.Services())
	maps.Copy(r.Services(), fresh)
	return nil
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
		query = `INSERT INTO services (id, name, backend_type, load_balancer_policy, health_check_path, weighted_targets, discovery_url, tls_client_config, health_check_port, health_check_protocol, health_check_type, l4_health_check_interval_ms, l4_health_check_timeout_ms, l4_udp_session_timeout_s, l4_proxy_protocol, unhealthy_threshold, healthy_threshold, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
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
				unhealthy_threshold = EXCLUDED.unhealthy_threshold,
				healthy_threshold = EXCLUDED.healthy_threshold,
				updated_at = CURRENT_TIMESTAMP`
	} else {
		query = `REPLACE INTO services (id, name, backend_type, load_balancer_policy, health_check_path, weighted_targets, discovery_url, tls_client_config, health_check_port, health_check_protocol, health_check_type, l4_health_check_interval_ms, l4_health_check_timeout_ms, l4_udp_session_timeout_s, l4_proxy_protocol, unhealthy_threshold, healthy_threshold, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`
	}

	_, err := r.db.Exec(r.dialect.Rebind(query), s.Id, s.Name, s.BackendType, s.LoadBalancerPolicy, s.HealthCheckPath, targetsStr, s.DiscoveryUrl, tlsStr, s.HealthCheckPort, s.HealthCheckProtocol, int32(s.HealthCheckType), s.L4HealthCheckIntervalMs, s.L4HealthCheckTimeoutMs, s.L4UdpSessionTimeoutS, s.L4ProxyProtocol, s.UnhealthyThreshold, s.HealthyThreshold)
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
