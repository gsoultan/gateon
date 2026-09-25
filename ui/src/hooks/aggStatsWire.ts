// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

export type AggStats = {
  totalRequests: number;
  totalBandwidthBytes: number;
  totalErrors: number;
  activeConnections: number;
  openCircuits: number;
  halfOpenCircuits: number;
  healthyTargets: number;
  totalTargets: number;
  cpuUsage: number;
  memoryUsage: number;
};

/**
 * /v1/diag/agg-stats answers in snake_case; this hook -- and the realtime
 * snapshot that later replaces its data -- speaks camelCase. Read as it came,
 * every field was undefined, so the health bar, the service cards and the
 * Circuit Breaker page showed nothing until a snapshot arrived.
 */
export function aggStatsFromWire(wire: Record<string, number | undefined>): AggStats {
  return {
    totalRequests: wire.total_requests ?? 0,
    totalBandwidthBytes: wire.total_bandwidth_bytes ?? 0,
    totalErrors: wire.total_errors ?? 0,
    activeConnections: wire.active_connections ?? 0,
    openCircuits: wire.open_circuits ?? 0,
    halfOpenCircuits: wire.half_open_circuits ?? 0,
    healthyTargets: wire.healthy_targets ?? 0,
    totalTargets: wire.total_targets ?? 0,
    cpuUsage: wire.cpu_usage ?? 0,
    memoryUsage: wire.memory_usage ?? 0,
  };
}
