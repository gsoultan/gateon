// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { expect, test } from "bun:test";
import { aggStatsFromWire } from "./aggStatsWire";

// The keys are the ones internal/server/handlers/diagnostics.go writes for
// GET /v1/diag/agg-stats. Read as camelCase they were all undefined.
test("agg-stats wire keys reach the dashboard's fields", () => {
  const stats = aggStatsFromWire({
    total_requests: 12, total_bandwidth_bytes: 34, total_errors: 5, active_connections: 6,
    open_circuits: 2, half_open_circuits: 1, healthy_targets: 7, total_targets: 9,
    cpu_usage: 11, memory_usage: 13,
  });
  expect(stats).toEqual({
    totalRequests: 12, totalBandwidthBytes: 34, totalErrors: 5, activeConnections: 6,
    openCircuits: 2, halfOpenCircuits: 1, healthyTargets: 7, totalTargets: 9,
    cpuUsage: 11, memoryUsage: 13,
  });
});
