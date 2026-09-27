// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, mock, test } from "bun:test";
import type { SystemMetrics } from "../types/metrics";

mock.module("../services/client", () => ({ api: {} }));

const { statusFromMetrics } = await import("./useGateonStatus");

// The system block of a metrics snapshot as the gateway encodes it. The keys are
// telemetry.SystemMetrics' JSON tags (internal/telemetry/metrics_snapshot.go),
// which TestMetricsSnapshotJSONMatchesTheDashboardTypes holds to
// ui/src/types/metrics.ts -- so this fixture cannot drift from the wire either.
const wire: SystemMetrics = {
  uptimeSeconds: 50.395464208,
  goroutines: 42,
  memoryAllocBytes: 64 * 1024 * 1024,
  memoryTotalAllocBytes: 512 * 1024 * 1024,
  memorySysBytes: 128 * 1024 * 1024,
  cpuUsagePercent: 16.7,
  memoryUsagePercent: 77.7,
  cpuCores: 15,
  memoryTotalGB: 16,
  storageUsageGB: 451.2,
  storageTotalGB: 464.2,
  storageUsagePercent: 97.2,
  publicIp: "",
  status: "running",
  version: "dev",
  titanEnabled: false,
  neuralSentinelEnabled: false,
  graphIntelligenceEnabled: false,
  predictiveAiEnabled: false,
  pqcEnabled: false,
  tpmEnabled: false,
  resourceGovernorEnabled: false,
};

describe("statusFromMetrics", () => {
  // Each live tick is merged over what /v1/status returned. These were read
  // under names the snapshot does not use, so every tick replaced the storage
  // figures /v1/status had supplied with 0 -- the card read "0.0GB / 0.0GB"
  // beside a correct 97.2% -- and left Total Memory at "N/A" for good.
  test("carries the storage and memory totals the gateway sends", () => {
    const status = statusFromMetrics(wire);
    expect(status.storageUsageGb).toBe(451.2);
    expect(status.storageTotalGb).toBe(464.2);
    expect(status.storageUsagePercent).toBe(97.2);
    expect(status.memoryTotalMb).toBe(16 * 1024);
  });
});
