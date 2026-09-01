// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package redis

import (
	"context"
	"strconv"
	"strings"

	redigo "github.com/redis/go-redis/v9"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Client defines the Redis operations used by Gateon.
type Client interface {
	redigo.Cmdable
	Subscribe(ctx context.Context, channels ...string) *redigo.PubSub
	Close() error
}

var Nil = redigo.Nil

// Options is the resolved connection configuration.
type Options struct {
	Addrs    []string
	Password string
	DB       int
}

// ClusterIgnoresDB reports that a database index was configured but cannot be
// honoured. Redis Cluster has no SELECT — every key lives in db 0 — so silently
// connecting to a different database than the operator asked for would be the
// kind of quiet mismatch that only shows up as missing data.
func (o Options) ClusterIgnoresDB() bool { return len(o.Addrs) > 1 && o.DB != 0 }

// ResolveOptions merges RedisConfig with environment overrides, returning false
// when no client should be created.
//
// Previously only the address survived the trip: inits.bootstrap copied
// gc.Redis.Addr into REDIS_ADDR and the client was built from that alone, so
// redis.password and redis.db were dropped. A password-protected Redis could not
// be configured at all, and every deployment shared db 0.
//
// Address presence remains the switch. RedisConfig.enabled is deliberately NOT
// consulted here even though the dashboard renders it and other UI copy says
// "Redis requires Redis enabled in Settings": nothing has ever read it, so a
// hand-written config with an address and no flag is a working deployment today,
// and proto3 cannot tell an unset bool from a false one. Starting to honour it
// would silently disconnect those. That is a deliberate behaviour change worth
// making on its own, with a release note, not smuggled into a fix for the
// password being dropped.
//
// getenv is injected so this is a pure function of its inputs.
func ResolveOptions(conf *gateonv1.RedisConfig, getenv func(string) string) (Options, bool) {
	var o Options
	addr := ""
	if conf != nil {
		addr = strings.TrimSpace(conf.GetAddr())
		o.Password = conf.GetPassword()
		o.DB = int(conf.GetDb())
	}

	// A config-file address is only honoured when redis.enabled is set. The flag
	// was previously read by nothing, so the dashboard toggle did not turn Redis
	// off, and an operator who unticked it kept a live connection.
	//
	// REDIS_ADDR is exempt and still enables Redis on its own. Setting that
	// variable is an unambiguous instruction with no accompanying flag to
	// contradict it, and it is how deployments that never touch the config file
	// are wired -- gating it on a flag they do not set would disconnect them.
	if conf != nil && !conf.GetEnabled() {
		addr = ""
	}

	// Environment wins: an orchestrator injecting a rotated secret should not be
	// overridden by a stale value in a config file.
	if v := strings.TrimSpace(getenv("REDIS_ADDR")); v != "" {
		addr = v
	}
	if v := getenv("REDIS_PASSWORD"); v != "" {
		o.Password = v
	}
	if v := strings.TrimSpace(getenv("REDIS_DB")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			o.DB = n
		}
	}

	for _, a := range strings.Split(addr, ",") {
		if a = strings.TrimSpace(a); a != "" {
			o.Addrs = append(o.Addrs, a)
		}
	}
	if len(o.Addrs) == 0 {
		return Options{}, false
	}
	if o.DB < 0 {
		o.DB = 0
	}
	return o, true
}

// NewClient returns a standard or cluster Redis client for the resolved options.
func NewClient(o Options) Client {
	if len(o.Addrs) > 1 {
		// ClusterOptions has no DB field; see ClusterIgnoresDB.
		return redigo.NewClusterClient(&redigo.ClusterOptions{
			Addrs:    o.Addrs,
			Password: o.Password,
		})
	}
	return redigo.NewClient(&redigo.Options{
		Addr:     o.Addrs[0],
		Password: o.Password,
		DB:       o.DB,
	})
}
