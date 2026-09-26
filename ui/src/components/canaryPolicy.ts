// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// A canary shifts traffic by shifting target weights, and only weighted round
// robin reads them. Normalised the way config.CanonicalLBPolicy does on the
// gateway, so the spellings the dashboard has written over time all count.
export function honoursWeights(policy: string | undefined): boolean {
  const key = (policy ?? "").toLowerCase().replace(/[_-]/g, "").trim();
  return key === "weightedroundrobin" || key === "wrr";
}
