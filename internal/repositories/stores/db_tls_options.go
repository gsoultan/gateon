// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package stores

import (
	"context"
	"database/sql"
	"maps"
	"strings"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type DBTLSOptionRegistry struct {
	*config.TLSOptionRegistry
	db      *sql.DB
	dialect db.Dialect
}

func NewDBTLSOptionRegistry(database *sql.DB, dialect db.Dialect) *DBTLSOptionRegistry {
	r := &DBTLSOptionRegistry{
		TLSOptionRegistry: config.NewEmptyTLSOptionRegistry(),
		db:                database,
		dialect:           dialect,
	}
	r.loadFromDB()
	return r
}

// loadFromDB fills the registry at construction. A failure is logged by
// reload and leaves the registry as it was: empty.
func (r *DBTLSOptionRegistry) loadFromDB() { _ = r.reload(context.Background()) }

// Reload replaces what the registry holds with what the database holds now:
// how a peer takes a change another gateway wrote (ADR 0081). A read that
// fails changes nothing and is returned.
func (r *DBTLSOptionRegistry) Reload(ctx context.Context) error { return r.reload(ctx) }

func (r *DBTLSOptionRegistry) reload(ctx context.Context) error {
	r.Mu().Lock()
	defer r.Mu().Unlock()

	query := "SELECT id, name, min_tls_version, max_tls_version, cipher_suites, alpn_protocols, client_auth_type, prefer_server_cipher_suites, sni_strict, client_authority_ids FROM tls_options"
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		// Returning quietly is how a schema mismatch here stayed invisible: the
		// registry simply came up empty, and a gateway with no TLS options looks
		// exactly like a gateway that was never given any.
		logger.L.LogError("cannot load TLS options; the gateway will start with none",
			"error", err)
		return err
	}
	defer rows.Close()

	// Collected first and stored only once every row is read: a read that
	// fails part way must not replace what the gateway is serving with the
	// part of it that arrived.
	fresh := make(map[string]*gateonv1.TLSOption)
	for rows.Next() {
		var opt gateonv1.TLSOption
		var ciphers, alpn, caIds string
		if err := rows.Scan(&opt.Id, &opt.Name, &opt.MinTlsVersion, &opt.MaxTlsVersion, &ciphers, &alpn, &opt.ClientAuthType, &opt.PreferServerCipherSuites, &opt.SniStrict, &caIds); err != nil {
			logRecordDropped("TLS option", "", "", err)
			continue
		}
		if ciphers != "" {
			opt.CipherSuites = strings.Split(ciphers, ",")
		}
		if alpn != "" {
			opt.AlpnProtocols = strings.Split(alpn, ",")
		}
		if caIds != "" {
			opt.ClientAuthorityIds = strings.Split(caIds, ",")
		}

		fresh[opt.Id] = &opt
	}
	if err := rows.Err(); err != nil {
		logLoadTruncated("TLS options", err)
		return err
	}
	clear(r.Options())
	maps.Copy(r.Options(), fresh)
	return nil
}

func (r *DBTLSOptionRegistry) Update(ctx context.Context, opt *gateonv1.TLSOption) error {
	r.Mu().Lock()
	defer r.Mu().Unlock()

	// All three are API-supplied and stored comma-joined in one column, so a
	// member containing a comma would be split back into two. See list_column.go.
	ciphers, err := joinListColumn("cipher suite", opt.CipherSuites)
	if err != nil {
		return err
	}
	alpn, err := joinListColumn("ALPN protocol", opt.AlpnProtocols)
	if err != nil {
		return err
	}
	caIds, err := joinListColumn("client authority ID", opt.ClientAuthorityIds)
	if err != nil {
		return err
	}

	var query string
	if r.dialect.Driver == db.DriverPostgres {
		query = `INSERT INTO tls_options (id, name, min_tls_version, max_tls_version, cipher_suites, alpn_protocols, client_auth_type, prefer_server_cipher_suites, sni_strict, client_authority_ids, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
			ON CONFLICT (id) DO UPDATE SET
				name = EXCLUDED.name,
				min_tls_version = EXCLUDED.min_tls_version,
				max_tls_version = EXCLUDED.max_tls_version,
				cipher_suites = EXCLUDED.cipher_suites,
				alpn_protocols = EXCLUDED.alpn_protocols,
				client_auth_type = EXCLUDED.client_auth_type,
				prefer_server_cipher_suites = EXCLUDED.prefer_server_cipher_suites,
				sni_strict = EXCLUDED.sni_strict,
				client_authority_ids = EXCLUDED.client_authority_ids,
				updated_at = CURRENT_TIMESTAMP`
	} else {
		query = `REPLACE INTO tls_options (id, name, min_tls_version, max_tls_version, cipher_suites, alpn_protocols, client_auth_type, prefer_server_cipher_suites, sni_strict, client_authority_ids, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`
	}

	if _, err := r.db.Exec(r.dialect.Rebind(query), opt.Id, opt.Name, opt.MinTlsVersion, opt.MaxTlsVersion, ciphers, alpn, opt.ClientAuthType, opt.PreferServerCipherSuites, opt.SniStrict, caIds); err != nil {
		return err
	}

	r.Options()[opt.Id] = opt
	return nil
}

func (r *DBTLSOptionRegistry) Delete(ctx context.Context, id string) error {
	r.Mu().Lock()
	defer r.Mu().Unlock()

	query := r.dialect.Rebind("DELETE FROM tls_options WHERE id = ?")
	if _, err := r.db.Exec(query, id); err != nil {
		return err
	}

	delete(r.Options(), id)
	return nil
}
