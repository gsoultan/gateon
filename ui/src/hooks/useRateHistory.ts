// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useEffect, useRef, useState } from "react";
import { useAggStats } from "./useAggStats";

/** One poll's worth of traffic, as rates. */
export interface RateSample {
  ts: number;
  requestsPerSecond: number;
  errorsPerSecond: number;
}

/** How many polls the hour keeps: an hour at the fastest refresh (5 s). */
export const RATE_HISTORY_CAP = 720;
const HOUR_MS = 60 * 60 * 1000;

/**
 * Request and error rates for the last hour, from the difference between
 * successive aggregate-stats polls. The gateway keeps hourly traffic buckets
 * for the longer ranges; it has no sub-hour history, so the last hour is
 * what this tab has seen since it opened. Bounded by count and by age.
 */
export function useRateHistory(): { samples: RateSample[]; isLoading: boolean } {
  const { data, isLoading } = useAggStats();
  const [samples, setSamples] = useState<RateSample[]>([]);
  const prev = useRef<{ requests: number; errors: number; ts: number } | null>(null);

  useEffect(() => {
    if (!data) return;
    const now = Date.now();
    const current = { requests: data.totalRequests ?? 0, errors: data.totalErrors ?? 0, ts: now };
    const last = prev.current;
    prev.current = current;
    if (!last) return;
    const seconds = (now - last.ts) / 1000;
    if (seconds <= 0) return;
    const sample: RateSample = {
      ts: now,
      requestsPerSecond: Math.max(0, current.requests - last.requests) / seconds,
      errorsPerSecond: Math.max(0, current.errors - last.errors) / seconds,
    };
    setSamples((history) => [...history, sample].filter((s) => s.ts >= now - HOUR_MS).slice(-RATE_HISTORY_CAP));
  }, [data]);

  return { samples, isLoading };
}
