// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

const MAX_POINTS = 12;

/**
 * The sparkline after one more poll: requests since the previous poll.
 *
 * The first poll has nothing before it, so it adds no point. It used to be
 * measured against zero, which made the first point the route's whole
 * lifetime count -- thousands of requests beside deltas of a few dozen -- and
 * flattened every real point against the floor for the two minutes it took to
 * scroll off. A counter that went backwards (a restart) adds zero.
 */
export function nextRouteHistory(history: number[], previousTotal: number | null, total: number): number[] {
  if (previousTotal === null) return history;
  return [...history, Math.max(0, total - previousTotal)].slice(-MAX_POINTS);
}
