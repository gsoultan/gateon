// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { ResourceGovernorStats, TitanStats } from "../../types/gateon";

export type StatusBadge = { label: string; color: string; detail: string };

// The Resource Governor badge said STABLE whenever the gateway reported a
// governor at all: at 95% memory, with a reading that had failed, and for a
// loop that was not running. It is read from what the loop last measured.
export function governorBadge(g: ResourceGovernorStats | undefined): StatusBadge {
  if (!g || !g.active) {
    return { label: "OFF", color: "gray", detail: "The monitoring loop is not running" };
  }
  if (g.readingsUnavailable) {
    return { label: "NO READING", color: "yellow", detail: "Memory or CPU usage could not be read" };
  }
  if (!g.sampled) {
    return { label: "STARTING", color: "gray", detail: "Waiting for the first reading" };
  }
  if (g.underPressure) {
    return { label: "UNDER PRESSURE", color: "red", detail: "Above a threshold; caches are being purged" };
  }
  return { label: "STABLE", color: "teal", detail: "Below both thresholds" };
}

// The Predictive AI badge said ON because a model was loaded, which it always
// is. The forecast only does anything for a service balanced with the
// Predictive policy, so the badge says whether one is.
export function predictorBadge(t: Pick<TitanStats, "aiPredictorEnabled" | "aiPolicyServiceCount">): StatusBadge {
  const n = t.aiPolicyServiceCount ?? 0;
  if (!t.aiPredictorEnabled) {
    return { label: "OFF", color: "gray", detail: "No model is loaded" };
  }
  if (n === 0) {
    return {
      label: "NOT IN USE",
      color: "gray",
      detail: "No service uses the Predictive load balancer policy",
    };
  }
  return {
    label: "IN USE",
    color: "indigo",
    detail: `Balancing ${n} ${n === 1 ? "service" : "services"}`,
  };
}
