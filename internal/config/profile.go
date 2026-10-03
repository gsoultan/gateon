// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"strings"
	"time"
)

// Tier is a resource profile preset. It sizes heavy subsystems (correlation
// engine, telemetry sketches, trace store, retention, Pebble, WAF) for the
// deployment's footprint without removing capabilities — every subsystem stays
// configurable; the tier only supplies conservative defaults.
type Tier string

const (
	// TierMinimal is the lowest-footprint profile: correlation and the trace
	// store off, tiny sketches, aggressive retention, request-phase-only WAF.
	TierMinimal Tier = "minimal"
	// TierStandard is the balanced default (~ current behavior).
	TierStandard Tier = "standard"
	// TierEnterprise maximizes detection depth and history at higher resource cost.
	TierEnterprise Tier = "enterprise"
)

// TierDefaults holds the per-subsystem defaults a tier supplies. A subsystem
// reads its own explicit config first and falls back to the matching field here.
type TierDefaults struct {
	Tier Tier

	// Correlation engine (internal/security/correlation).
	CorrelationEnabled      bool
	CorrelationMaxSources   int
	CorrelationMaxPerSource int

	// Database connection pool.
	DBMaxOpenConns int
	DBMaxIdleConns int

	// Telemetry.
	TelemetryIntervalSeconds int
	FlushIntervalSeconds     int
	TraceStoreEnabled        bool // open the Pebble trace store at all
	// TraceSampleRate is 1 = every request, N = 1-in-N, 0 = none.
	//
	// Minimal is 0 because its trace store is closed: the header maps were being
	// cloned and the record populated per request and then dropped on the floor
	// at recordTraceToStore. That is pure waste and removing it changes nothing
	// anyone can observe.
	//
	// Standard and enterprise are both 1 — every request — which is the
	// behaviour every existing install already has. Turning standard down would
	// cut roughly 7 allocations per request, but it would also mean the trace
	// view stops showing every successful request, and changing a default
	// silently re-prices every deployment that already relies on it. It is left
	// as an operator decision via GATEON_TRACE_SAMPLE_RATE, which is now safe to
	// use because failed requests are recorded regardless of the rate.
	TraceSampleRate uint32
	CMSWidth        int // Count-Min Sketch width
	CMSDepth        int // Count-Min Sketch depth
	EbpfPollSeconds int // eBPF stats poll interval

	// Storage (Pebble + SQL retention).
	RetentionDays       int
	PebbleCacheBytes    int64
	PebbleMemTableBytes int64
	PebbleMaxOpenFiles  int

	// AccessLogMaxPerSecond caps the access-log lines written in one second,
	// across the gateway (ADR 0049). Under journald's default rate limit --
	// 10000 lines in 30 s -- an uncapped per-request log silenced the service's
	// ERRORs and security events above ~333 req/s. The cap leaves that budget
	// to them. GATEON_ACCESS_LOG_MAX_PER_SECOND overrides it; 0 lifts it.
	AccessLogMaxPerSecond int

	// TraceStoreMaxBytes is the most disk the live trace store may use; past
	// it the oldest traces are evicted whatever their age (ADR 0049). Age alone
	// bounded it before, which bounds nothing against traffic: ~1.1 KB a
	// request is ~66 GB a week at 100 req/s. GATEON_TRACE_STORE_MAX_MB
	// overrides it (internal/telemetry/tracebudget).
	TraceStoreMaxBytes int64

	// Trace archive (internal/telemetry/tracearchive): how long archived hours
	// of traces are kept, and the most disk they may take, whichever binds
	// first. The archive itself is off on every tier until it is enabled --
	// turning it on writes to disk every existing install has budgeted for
	// something else -- so these only size it once someone has.
	TraceArchiveRetentionDays int
	TraceArchiveMaxBytes      int64

	// WAF default tier when WafConfig.Tier is empty.
	WAFTier Tier

	// RLLimiterStates caps how many per-IP reinforcement-learning states the
	// adaptive rate limiter keeps (internal/ai). The keys are remote addresses
	// chosen by whoever is sending traffic, so this is an adversary-controlled
	// structure and needs an explicit ceiling, not a natural one. Each entry is
	// a few dozen bytes; the ceiling is about bounding worst-case growth, not
	// steady-state cost.
	RLLimiterStates int

	// EntryPointMaxConnections is how many connections an entrypoint holds
	// open at once when its own max_connections is 0: on a TCP entrypoint L4
	// sessions and connections still being inspected, on an HTTP one its
	// HTTP/1 and HTTP/2 connections, idle keep-alive ones included, and the
	// QUIC connections of HTTP/3 (ADR 0032). A connection costs a client one
	// SYN and the gateway a goroutine or two, buffers and descriptors -- six
	// for a spliced L4 session -- so without a ceiling a flood of them is paid
	// for by the gateway alone.
	EntryPointMaxConnections int

	// EntryPointMaxConnPerAddr is how many concurrent connections one source
	// address may hold on a single entrypoint (ADR 0036). EntryPointMaxConnections
	// bounds what a flood costs the gateway; it does not bound who pays, so one
	// client could fill an entrypoint by itself. This is the tighter, per-client
	// bound: a connection past it is refused at accept. Loopback and
	// GATEON_MITIGATION_ALLOWLIST are exempt, so a local proxy -- behind which
	// every client is loopback -- is never capped by the address it shares.
	// The map that counts holds an entry only while an address has a connection
	// open, so it is bounded by EntryPointMaxConnections, not by the address
	// space. GATEON_ENTRYPOINT_MAX_CONN_PER_ADDR overrides it; 0 disables it.
	EntryPointMaxConnPerAddr int

	// MaxHeaderBytes is the most request-header bytes an HTTP listener --
	// every entrypoint and the management listener, over HTTP/1, HTTP/2 and
	// HTTP/3 -- buffers for one request; a request past it is refused with 431
	// (ADR 0042). A connection still sending its header holds up to this much,
	// and EntryPointMaxConnections such connections are what one tier must
	// survive, so the product of the two is sized against the tier's memory --
	// the arithmetic is in the ADR. It used to be 1 MiB everywhere, which at
	// the minimal tier's 1000 connections is more than the 2 GB host has.
	// GATEON_MAX_HEADER_BYTES overrides it.
	MaxHeaderBytes int

	// StreamIdleTimeout and StreamMaxLifetime bound a response that is allowed
	// to outlive its entrypoint's per-request deadlines: a WebSocket tunnel
	// once the backend has answered 101, and a response the server answered
	// as text/event-stream (ADR 0042). Idle ends it when no byte has moved in
	// either direction for that long; MaxLifetime ends it that long after it
	// began, however busy. GATEON_STREAM_IDLE_TIMEOUT and
	// GATEON_STREAM_MAX_LIFETIME override them; 0 disables either.
	StreamIdleTimeout time.Duration
	StreamMaxLifetime time.Duration
}

// NormalizeTier coerces an arbitrary string to a known tier, defaulting to
// TierStandard for empty/unknown values.
func NormalizeTier(s string) Tier {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(TierMinimal):
		return TierMinimal
	case string(TierEnterprise):
		return TierEnterprise
	case string(TierStandard):
		return TierStandard
	default:
		return TierStandard
	}
}

// ResolveProfile determines the active tier. The GATEON_PROFILE environment
// variable wins (so a container can pin its footprint regardless of stored
// config); otherwise GlobalConfig.profile is used; otherwise TierStandard.
func ResolveProfile() Tier {
	if env := strings.TrimSpace(os.Getenv("GATEON_PROFILE")); env != "" {
		return NormalizeTier(env)
	}
	if gc := GetGlobalConfig(); gc != nil && gc.Profile != "" {
		return NormalizeTier(gc.Profile)
	}
	return TierStandard
}

// DefaultsFor returns the conservative defaults for a tier.
func DefaultsFor(tier Tier) TierDefaults {
	switch tier {
	case TierMinimal:
		return TierDefaults{
			Tier:                      TierMinimal,
			CorrelationEnabled:        false,
			CorrelationMaxSources:     500,
			CorrelationMaxPerSource:   32,
			TraceStoreEnabled:         false,
			TraceSampleRate:           0,
			CMSWidth:                  512,
			CMSDepth:                  3,
			EbpfPollSeconds:           10,
			RetentionDays:             1,
			PebbleCacheBytes:          4 << 20, // 4 MiB
			PebbleMemTableBytes:       1 << 20, // 1 MiB
			PebbleMaxOpenFiles:        50,
			TraceStoreMaxBytes:        256 << 20, // 256 MiB
			AccessLogMaxPerSecond:     50,
			TraceArchiveRetentionDays: 7,
			TraceArchiveMaxBytes:      256 << 20, // 256 MiB
			DBMaxOpenConns:            5,
			DBMaxIdleConns:            5,
			TelemetryIntervalSeconds:  30,
			FlushIntervalSeconds:      10,
			WAFTier:                   TierMinimal,
			RLLimiterStates:           2000,
			EntryPointMaxConnections:  1000,
			EntryPointMaxConnPerAddr:  128,
			MaxHeaderBytes:            32 << 10, // 32 KiB
			StreamIdleTimeout:         2 * time.Minute,
			StreamMaxLifetime:         time.Hour,
		}
	case TierEnterprise:
		return TierDefaults{
			Tier:                      TierEnterprise,
			CorrelationEnabled:        true,
			CorrelationMaxSources:     10000,
			CorrelationMaxPerSource:   256,
			TraceStoreEnabled:         true,
			TraceSampleRate:           1,
			CMSWidth:                  4096,
			CMSDepth:                  4,
			EbpfPollSeconds:           2,
			RetentionDays:             30,
			PebbleCacheBytes:          32 << 20, // 32 MiB
			PebbleMemTableBytes:       8 << 20,  // 8 MiB
			PebbleMaxOpenFiles:        500,
			TraceStoreMaxBytes:        20 << 30, // 20 GiB
			AccessLogMaxPerSecond:     200,
			TraceArchiveRetentionDays: 365,
			TraceArchiveMaxBytes:      20 << 30, // 20 GiB
			DBMaxOpenConns:            100,
			DBMaxIdleConns:            50,
			TelemetryIntervalSeconds:  2,
			FlushIntervalSeconds:      1,
			WAFTier:                   TierEnterprise,
			RLLimiterStates:           100000,
			EntryPointMaxConnections:  50000,
			EntryPointMaxConnPerAddr:  1024,
			MaxHeaderBytes:            64 << 10, // 64 KiB
			StreamIdleTimeout:         10 * time.Minute,
			StreamMaxLifetime:         12 * time.Hour,
		}
	default: // TierStandard
		return TierDefaults{
			Tier:                      TierStandard,
			CorrelationEnabled:        true,
			CorrelationMaxSources:     2000,
			CorrelationMaxPerSource:   64,
			TraceStoreEnabled:         true,
			TraceSampleRate:           1,
			CMSWidth:                  2048,
			CMSDepth:                  4,
			EbpfPollSeconds:           2,
			RetentionDays:             7,
			PebbleCacheBytes:          8 << 20, // 8 MiB
			PebbleMemTableBytes:       4 << 20, // 4 MiB
			PebbleMaxOpenFiles:        200,
			TraceStoreMaxBytes:        2 << 30, // 2 GiB
			AccessLogMaxPerSecond:     100,
			TraceArchiveRetentionDays: 90,
			TraceArchiveMaxBytes:      2 << 30, // 2 GiB
			DBMaxOpenConns:            25,
			DBMaxIdleConns:            25,
			TelemetryIntervalSeconds:  5,
			FlushIntervalSeconds:      2,
			WAFTier:                   TierStandard,
			RLLimiterStates:           20000,
			EntryPointMaxConnections:  10000,
			EntryPointMaxConnPerAddr:  256,
			MaxHeaderBytes:            32 << 10, // 32 KiB
			StreamIdleTimeout:         5 * time.Minute,
			StreamMaxLifetime:         4 * time.Hour,
		}
	}
}

// CurrentTierDefaults resolves the active profile and returns its defaults.
func CurrentTierDefaults() TierDefaults {
	return DefaultsFor(ResolveProfile())
}
