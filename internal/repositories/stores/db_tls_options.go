// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package stores

import (
	"context"
	"database/sql"
	"strings"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/db"
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

func (r *DBTLSOptionRegistry) loadFromDB() {
	r.Mu().Lock()
	defer r.Mu().Unlock()

	query := "SELECT id, name, min_tls_version, max_tls_version, cipher_suites, alpn_protocols, client_auth_type, prefer_server_cipher_suites, sni_strict, client_authority_ids FROM tls_options"
	rows, err := r.db.Query(query)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var opt gateonv1.TLSOption
		var ciphers, alpn, caIds string
		if err := rows.Scan(&opt.Id, &opt.Name, &opt.MinTlsVersion, &opt.MaxTlsVersion, &ciphers, &alpn, &opt.ClientAuthType, &opt.PreferServerCipherSuites, &opt.SniStrict, &caIds); err != nil {
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

		r.Options()[opt.Id] = &opt
	}
}

func (r *DBTLSOptionRegistry) Update(ctx context.Context, opt *gateonv1.TLSOption) error {
	r.Mu().Lock()
	defer r.Mu().Unlock()

	ciphers := strings.Join(opt.CipherSuites, ",")
	alpn := strings.Join(opt.AlpnProtocols, ",")
	caIds := strings.Join(opt.ClientAuthorityIds, ",")

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

	_, err := r.db.Exec(r.dialect.Rebind(query), opt.Id, opt.Name, opt.MinTlsVersion, opt.MaxTlsVersion, ciphers, alpn, opt.ClientAuthType, opt.PreferServerCipherSuites, opt.SniStrict, caIds)
	if err != nil {
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
