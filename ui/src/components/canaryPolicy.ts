// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Round robin -- the default policy -- and weighted round robin read target
// weights (ADR 0047); least connections and the predictive balancer do not.
// Normalised the way config.CanonicalLBPolicy does on the gateway, so the
// spellings the dashboard has written over time all count.
export function honoursWeights(policy: string | undefined): boolean {
  const key = (policy ?? "").toLowerCase().replace(/[_-]/g, "").trim();
  return ["", "roundrobin", "rr", "weightedroundrobin", "wrr"].includes(key);
}
