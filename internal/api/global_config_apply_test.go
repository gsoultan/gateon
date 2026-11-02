// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// countingInvalidator counts the route rebuilds it is asked for.
type countingInvalidator struct {
	mu     sync.Mutex
	routes int
}

func (c *countingInvalidator) InvalidateRoute(string) {}
func (c *countingInvalidator) InvalidateRoutes(func(*gateonv1.Route) bool) {
	c.mu.Lock()
	c.routes++
	c.mu.Unlock()
}
func (c *countingInvalidator) InvalidateTLS() {}
func (c *countingInvalidator) InvalidateWAF() {}

func (c *countingInvalidator) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.routes
}

// TestAGlobalChangeStoredOutsideTheAPIIsApplied: a GitOps sync stores the
// configuration it pulled straight into the registry, as do the fixes applied
// from Diagnostics and first-run setup. Only UpdateGlobalConfig reconfigured
// the running gateway, so a WAF switched off in the synced repository kept
// running -- the route chains it is built into were never rebuilt.
func TestAGlobalChangeStoredOutsideTheAPIIsApplied(t *testing.T) {
	reg := config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))
	inv := &countingInvalidator{}
	NewApiService(ApiServiceConfig{Globals: reg, Invalidator: inv})

	gc := reg.Get(t.Context())
	gc.Waf.Enabled = !gc.Waf.GetEnabled()
	if err := reg.Update(t.Context(), gc); err != nil { // as GitOpsManager.sync does
		t.Fatal(err)
	}
	if inv.count() == 0 {
		t.Fatal("a change stored in the registry rebuilt no route: the gateway kept the configuration it had")
	}
}

// TestUpdateGlobalConfigAppliesOnceWhenTheStoreReports: with the registry
// reporting changes, the RPC must not apply the same change a second time --
// every apply starts an IP reputation feed refresh.
func TestUpdateGlobalConfigAppliesOnceWhenTheStoreReports(t *testing.T) {
	reg := config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))
	inv := &countingInvalidator{}
	s := NewApiService(ApiServiceConfig{Globals: reg, Invalidator: inv})

	gc := reg.Get(t.Context())
	gc.Waf.Enabled = !gc.Waf.GetEnabled()
	if _, err := s.UpdateGlobalConfig(t.Context(), &gateonv1.UpdateGlobalConfigRequest{Config: gc}); err != nil {
		t.Fatal(err)
	}
	if n := inv.count(); n != 1 {
		t.Fatalf("one save rebuilt the routes %d times, want 1", n)
	}
}

// TestSavingGeoIPReopensEveryDatabaseItNames: the GeoIP card applies when
// saved, but only the City database was reopened. The ASN and Country paths
// were read once at start, so a new ASN database showed nothing until a
// restart.
func TestSavingGeoIPReopensEveryDatabaseItNames(t *testing.T) {
	var opened []string
	record := func(kind string) func(string) error {
		return func(path string) error { opened = append(opened, kind+"="+path); return nil }
	}
	reg := config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))
	s := &ApiService{Globals: reg, geoip: &geoipLoaders{city: record("city"), asn: record("asn"), country: record("country")}}

	gc := reg.Get(t.Context())
	gc.Geoip = &gateonv1.GeoIPConfig{Enabled: true, DbPath: "c.mmdb", AsnDbPath: "a.mmdb", CountryDbPath: "k.mmdb"}
	if _, err := s.UpdateGlobalConfig(t.Context(), &gateonv1.UpdateGlobalConfigRequest{Config: gc}); err != nil {
		t.Fatal(err)
	}
	want := []string{"city=c.mmdb", "asn=a.mmdb", "country=k.mmdb"}
	if !slices.Equal(opened, want) {
		t.Fatalf("a save opened %v, want %v", opened, want)
	}

	opened = nil
	gc.Geoip.Enabled = false
	if _, err := s.UpdateGlobalConfig(t.Context(), &gateonv1.UpdateGlobalConfigRequest{Config: gc}); err != nil {
		t.Fatal(err)
	}
	if len(opened) != 0 {
		t.Fatalf("with GeoIP off a save opened %v", opened)
	}
}
