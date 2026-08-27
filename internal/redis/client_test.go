// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package redis

import (
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// noEnv stands in for a process with none of the REDIS_* variables set.
func noEnv(string) string { return "" }

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// TestPasswordAndDBReachTheClient is the regression guard. inits.bootstrap
// copied only Addr into REDIS_ADDR and the client was built from that alone, so
// a password-protected Redis could not be configured and every deployment shared
// db 0.
func TestPasswordAndDBReachTheClient(t *testing.T) {
	conf := &gateonv1.RedisConfig{Addr: "redis:6379", Password: "s3cret", Db: 4}

	got, ok := ResolveOptions(conf, noEnv)
	if !ok {
		t.Fatal("an address was configured but no client would be created")
	}
	if got.Password != "s3cret" {
		t.Errorf("Password = %q, want it carried through from config", got.Password)
	}
	if got.DB != 4 {
		t.Errorf("DB = %d, want 4", got.DB)
	}
	if len(got.Addrs) != 1 || got.Addrs[0] != "redis:6379" {
		t.Errorf("Addrs = %v, want [redis:6379]", got.Addrs)
	}
}

// Address presence is the switch, as it always has been. Honouring a separate
// `enabled` flag would disconnect deployments that set an address without it.
func TestNoAddressMeansNoClient(t *testing.T) {
	for _, tc := range []struct {
		name string
		conf *gateonv1.RedisConfig
	}{
		{"nil config", nil},
		{"empty config", &gateonv1.RedisConfig{}},
		{"whitespace address", &gateonv1.RedisConfig{Addr: "   "}},
		{"password but no address", &gateonv1.RedisConfig{Password: "s3cret"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := ResolveOptions(tc.conf, noEnv); ok {
				t.Fatal("a client would be created with no address")
			}
		})
	}
}

// REDIS_ADDR alone must still work: it is how every existing deployment is
// configured, via inits.bootstrap copying the address into the environment.
func TestEnvironmentOnlyStillWorks(t *testing.T) {
	got, ok := ResolveOptions(nil, envMap(map[string]string{"REDIS_ADDR": "cache:6379"}))
	if !ok {
		t.Fatal("REDIS_ADDR alone did not produce a client")
	}
	if len(got.Addrs) != 1 || got.Addrs[0] != "cache:6379" {
		t.Errorf("Addrs = %v, want [cache:6379]", got.Addrs)
	}
}

// An orchestrator injecting a rotated secret must win over a stale config file.
func TestEnvironmentOverridesConfig(t *testing.T) {
	conf := &gateonv1.RedisConfig{Addr: "stale:6379", Password: "old", Db: 1}
	got, ok := ResolveOptions(conf, envMap(map[string]string{
		"REDIS_ADDR": "fresh:6379", "REDIS_PASSWORD": "rotated", "REDIS_DB": "7",
	}))
	if !ok {
		t.Fatal("no client produced")
	}
	if got.Addrs[0] != "fresh:6379" || got.Password != "rotated" || got.DB != 7 {
		t.Errorf("got %+v, want the environment values to win", got)
	}
}

// A malformed REDIS_DB must leave the configured value alone rather than
// silently selecting db 0, which would point at the wrong dataset.
func TestUnparseableEnvDBFallsBackToConfig(t *testing.T) {
	conf := &gateonv1.RedisConfig{Addr: "redis:6379", Db: 3}
	for _, bad := range []string{"abc", "-1", "", "  "} {
		got, ok := ResolveOptions(conf, envMap(map[string]string{"REDIS_DB": bad}))
		if !ok {
			t.Fatalf("%q: no client produced", bad)
		}
		if got.DB != 3 {
			t.Errorf("REDIS_DB=%q: DB = %d, want the configured 3", bad, got.DB)
		}
	}
}

func TestCommaSeparatedAddressesBecomeACluster(t *testing.T) {
	conf := &gateonv1.RedisConfig{Addr: "a:6379, b:6379 ,c:6379", Password: "p"}
	got, ok := ResolveOptions(conf, noEnv)
	if !ok {
		t.Fatal("no client produced")
	}
	if len(got.Addrs) != 3 {
		t.Fatalf("Addrs = %v, want three entries with whitespace trimmed", got.Addrs)
	}
	if got.Addrs[1] != "b:6379" {
		t.Errorf("Addrs[1] = %q, want whitespace trimmed", got.Addrs[1])
	}
}

// Redis Cluster has no SELECT, so a configured db cannot be honoured there. It
// must be reported, not silently ignored — the symptom is otherwise just data
// that is not where the operator expects it.
func TestClusterReportsThatItCannotHonourTheDB(t *testing.T) {
	cluster, _ := ResolveOptions(&gateonv1.RedisConfig{Addr: "a:6379,b:6379", Db: 2}, noEnv)
	if !cluster.ClusterIgnoresDB() {
		t.Error("a cluster with db=2 did not report that the db is ignored")
	}

	clusterDefault, _ := ResolveOptions(&gateonv1.RedisConfig{Addr: "a:6379,b:6379"}, noEnv)
	if clusterDefault.ClusterIgnoresDB() {
		t.Error("a cluster on the default db reported a problem it does not have")
	}

	single, _ := ResolveOptions(&gateonv1.RedisConfig{Addr: "a:6379", Db: 2}, noEnv)
	if single.ClusterIgnoresDB() {
		t.Error("a single-node client can honour the db and must not report otherwise")
	}
}
