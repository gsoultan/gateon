// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { RateSample } from "../../hooks/useRateHistory";
import type { TrafficSample } from "../../types/metrics";

export const TRAFFIC_RANGES = ["1h", "24h", "7d"] as const;
export type TrafficRange = (typeof TRAFFIC_RANGES)[number];

export interface Point {
  ts: number;
  value: number;
}

export interface TrafficSeries {
  /** Requests per second over the range. */
  requests: Point[];
  /** Errors per second; empty when the range has no error history. */
  errors: Point[];
  /** Why the errors line is missing, when it is. */
  note?: string;
}

const RANGE_MS: Record<TrafficRange, number> = {
  "1h": 60 * 60 * 1000,
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
};
const HOUR_SECONDS = 3600;

export function asTrafficRange(value: string | undefined): TrafficRange {
  return TRAFFIC_RANGES.find((r) => r === value) ?? "1h";
}

/**
 * The lines of the Traffic now chart. The last hour is what this tab has
 * polled since it opened, so it has errors; the longer ranges are the
 * gateway's hourly buckets, which record requests and bytes only, so the
 * errors line is left out and the chart says so rather than drawing zero.
 */
export function trafficSeries(
  range: TrafficRange,
  session: RateSample[],
  hourly: TrafficSample[] | null | undefined,
  now = Date.now(),
): TrafficSeries {
  const since = now - RANGE_MS[range];
  if (range === "1h") {
    const recent = session.filter((s) => s.ts >= since);
    return {
      requests: recent.map((s) => ({ ts: s.ts, value: s.requestsPerSecond })),
      errors: recent.map((s) => ({ ts: s.ts, value: s.errorsPerSecond })),
    };
  }
  const buckets = (hourly ?? []).filter((b) => b.ts >= since).sort((a, b) => a.ts - b.ts);
  return {
    requests: buckets.map((b) => ({ ts: b.ts, value: b.requests / HOUR_SECONDS })),
    errors: [],
    note: "Errors are kept for the last hour only.",
  };
}
