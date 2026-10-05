// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

export interface DependencySummary {
  label: string;
  color: string;
}

/**
 * The Infrastructure Dependencies badge, counted from the checks the gateway
 * reported. It replaces a hard-coded "All checks active", which stood beside
 * dependencies the same card showed as Degraded (truth T41).
 */
export function dependencySummary(deps: { healthy?: boolean }[]): DependencySummary {
  if (deps.length === 0) return { label: "No checks reported", color: "gray" };
  const degraded = deps.filter((d) => !d.healthy).length;
  if (degraded === 0) return { label: `All ${deps.length} healthy`, color: "teal" };
  return { label: `${degraded} of ${deps.length} degraded`, color: "red" };
}
