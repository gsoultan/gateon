// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package geoiptest

import (
	"net"
	"testing"

	"github.com/oschwald/geoip2-golang"
)

// TestTheDatabaseIsReadLikeAMaxMindOne proves the fixture: the reader the
// gateway uses opens it and places both addresses.
func TestTheDatabaseIsReadLikeAMaxMindOne(t *testing.T) {
	db, err := geoip2.Open(WriteCountryDB(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for ip, want := range map[string]string{USAddress: "US", CNAddress: "CN"} {
		rec, err := db.Country(net.ParseIP(ip))
		if err != nil {
			t.Fatalf("Country(%s): %v", ip, err)
		}
		if rec.Country.IsoCode != want {
			t.Errorf("Country(%s) = %q, want %q", ip, rec.Country.IsoCode, want)
		}
	}
}
