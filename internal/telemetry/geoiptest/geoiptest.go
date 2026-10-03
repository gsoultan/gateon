// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package geoiptest writes a real MaxMind DB for tests: a GeoLite2-Country
// layout, IPv4, in which 0.0.0.0/1 is "US" and 128.0.0.0/1 is "CN" (so
// 8.8.8.8 is US and 203.0.113.9 is CN).
//
// It is built byte by byte from the MaxMind DB format specification because no
// test database ships with the reader, and a stubbed resolver would not prove
// that the gateway opens and queries a database the way it does in production.
// It is imported only by tests.
package geoiptest

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// The addresses the database places, and where.
const (
	USAddress = "8.8.8.8"
	CNAddress = "203.0.113.9"
)

// WriteCountryDB writes the database into a temporary directory of t and
// returns its path.
func WriteCountryDB(t testing.TB) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "GeoLite2-Country.mmdb")
	if err := os.WriteFile(path, CountryDB(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// CountryDB is the database's bytes.
func CountryDB() []byte {
	us := mmdbMap(mmdbStr("country"), mmdbMap(mmdbStr("iso_code"), mmdbStr("US")))
	cn := mmdbMap(mmdbStr("country"), mmdbMap(mmdbStr("iso_code"), mmdbStr("CN")))
	// One search-tree node. A record value past node_count points into the
	// data section at value - node_count - 16 (the separator).
	const nodeCount, separator = 1, 16
	var db []byte
	db = append(db, mmdbRecord24(nodeCount+separator)...)
	db = append(db, mmdbRecord24(nodeCount+separator+len(us))...)
	db = append(db, make([]byte, separator)...)
	db = append(db, us...)
	db = append(db, cn...)
	db = append(db, "\xab\xcd\xefMaxMind.com"...)
	return append(db, mmdbMetadata()...)
}

func mmdbMetadata() []byte {
	return mmdbMap(
		mmdbStr("node_count"), mmdbUint(6, 1),
		mmdbStr("record_size"), mmdbUint(5, 24),
		mmdbStr("ip_version"), mmdbUint(5, 4),
		mmdbStr("database_type"), mmdbStr("GeoLite2-Country"),
		mmdbStr("languages"), []byte{0x00, 0x04}, // empty array (extended type 11)
		mmdbStr("binary_format_major_version"), mmdbUint(5, 2),
		mmdbStr("binary_format_minor_version"), mmdbUint(5, 0),
		mmdbStr("build_epoch"), []byte{0x01, 0x02, 0x01}, // uint64 1 (extended type 9)
		mmdbStr("description"), mmdbMap(mmdbStr("en"), mmdbStr("gateon test country database")),
	)
}

func mmdbRecord24(v int) []byte { return []byte{byte(v >> 16), byte(v >> 8), byte(v)} }

func mmdbStr(s string) []byte { return append([]byte{0x40 | byte(len(s))}, s...) }

// mmdbUint encodes v as MaxMind type typ (5 = uint16, 6 = uint32) in two bytes.
func mmdbUint(typ byte, v uint16) []byte {
	b := binary.BigEndian.AppendUint16(nil, v)
	return append([]byte{typ<<5 | byte(len(b))}, b...)
}

func mmdbMap(kv ...[]byte) []byte {
	out := []byte{0xE0 | byte(len(kv)/2)}
	for _, p := range kv {
		out = append(out, p...)
	}
	return out
}
