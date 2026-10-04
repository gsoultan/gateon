// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"database/sql"
	"fmt"
	"net/netip"
	"time"
)

// ADR 0058. An address shun is kept, and enforced, per IPv4 address and per
// IPv6 /64, as the kernel's shun map already kept it. A row written before
// under one IPv6 address would no longer be read by anything: enforcement
// looks the /64 up. So each IPv6 row moves to its /64's key, the network
// address ("2001:db8:1:2::"), and a v4-mapped one to its IPv4 address. Rows
// of one /64 become one; the row kept is the one that refuses the most (see
// strongerShunRow).
func init() {
	Register(68, "ip_mitigations_ipv6_by_slash64", rekeyIPv6Mitigations)
}

// legacyIPv6KeyBits is the width migration 68 keys an IPv6 row by. Frozen: it
// describes what the migration did, so a later change to the live keying
// (repid.AddressKey) must not change it.
const legacyIPv6KeyBits = 64

// shunRow is one ip_mitigations row as migration 68 moves it.
type shunRow struct {
	ip, status, reason                               string
	mitigatedAt, unmitigatedAt, updatedAt, expiresAt sql.NullTime
}

// migratedIPv6Key is the key migration 68 gives ip, and whether it moves.
func migratedIPv6Key(ip string) (string, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}
	a = a.Unmap().WithZone("")
	if a.Is6() {
		p, err := a.Prefix(legacyIPv6KeyBits)
		if err != nil {
			return "", false
		}
		a = p.Addr()
	}
	key := a.String()
	return key, key != ip
}

func rekeyIPv6Mitigations(conn *sql.DB, dialect Dialect) error {
	rows, err := readColonKeyedShuns(conn, dialect)
	if err != nil {
		return err
	}
	groups := map[string][]shunRow{}
	moves := map[string]bool{}
	for _, r := range rows {
		key, moved := migratedIPv6Key(r.ip)
		if key == "" {
			continue // not an address; left as it is, read by nothing new
		}
		groups[key] = append(groups[key], r)
		moves[key] = moves[key] || moved
	}
	now := time.Now()
	for key, group := range groups {
		if !moves[key] {
			continue
		}
		if err := mergeShunRows(conn, dialect, key, group, now); err != nil {
			return fmt.Errorf("move the IPv6 shuns of %s: %w", key, err)
		}
	}
	return nil
}

// readColonKeyedShuns reads every row whose key could be IPv6 text.
func readColonKeyedShuns(conn *sql.DB, dialect Dialect) ([]shunRow, error) {
	rows, err := conn.Query(dialect.Rebind(`SELECT ip, status, COALESCE(reason, ''), mitigated_at,
		unmitigated_at, updated_at, expires_at FROM ip_mitigations WHERE ip LIKE '%:%'`))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []shunRow
	for rows.Next() {
		var r shunRow
		if err := rows.Scan(&r.ip, &r.status, &r.reason, &r.mitigatedAt, &r.unmitigatedAt, &r.updatedAt, &r.expiresAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// mergeShunRows replaces a /64's rows with one, under key, in one transaction.
func mergeShunRows(conn *sql.DB, dialect Dialect, key string, group []shunRow, now time.Time) error {
	keep := group[0]
	for _, r := range group[1:] {
		if strongerShunRow(r, keep, now) {
			keep = r
		}
	}
	tx, err := conn.Begin()
	if err != nil {
		return err
	}
	del := dialect.Rebind(`DELETE FROM ip_mitigations WHERE ip = ?`)
	for _, r := range append(group, shunRow{ip: key}) {
		if _, err := tx.Exec(del, r.ip); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	ins := dialect.Rebind(`INSERT INTO ip_mitigations (ip, status, reason, mitigated_at, unmitigated_at, updated_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if _, err := tx.Exec(ins, key, keep.status, keep.reason, migratedTime(keep.mitigatedAt),
		migratedTime(keep.unmitigatedAt), migratedTime(keep.updatedAt), migratedTime(keep.expiresAt)); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// strongerShunRow reports whether a refuses more than b at now: a shun in
// force over one that is not -- an operator's open-ended block over any that
// lapses, a later end over an earlier -- then a release over a lapsed shun,
// the later release first, then whichever was written later.
func strongerShunRow(a, b shunRow, now time.Time) bool {
	fa, fb := inForce(a, now), inForce(b, now)
	ra, rb := a.status == "unmitigated", b.status == "unmitigated"
	switch {
	case fa != fb:
		return fa
	case fa:
		return !a.expiresAt.Valid && b.expiresAt.Valid ||
			a.expiresAt.Valid && b.expiresAt.Valid && a.expiresAt.Time.After(b.expiresAt.Time)
	case ra != rb:
		return ra
	}
	return a.updatedAt.Valid && (!b.updatedAt.Valid || a.updatedAt.Time.After(b.updatedAt.Time))
}

func inForce(r shunRow, now time.Time) bool {
	return r.status == "mitigated" && (!r.expiresAt.Valid || r.expiresAt.Time.After(now))
}

// migratedTime writes a time back as ip_mitigations times are written and
// compared: UTC, to the second (telemetry's sqlUTC), or NULL.
func migratedTime(t sql.NullTime) any {
	if !t.Valid {
		return nil
	}
	return t.Time.UTC().Format(time.DateTime)
}
