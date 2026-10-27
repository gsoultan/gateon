// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

/**
 * The five states a status chip can show, and nothing else.
 *
 * - up: serving and checked healthy.
 * - degraded: serving with a problem the operator should see (an audit-only
 *   WAF, a certificate about to expire, one target down).
 * - down: not serving.
 * - off: switched off on purpose.
 * - unknown: not computed. Shown instead of a zero (ADR 0048).
 */
export type StatusState = "up" | "degraded" | "down" | "off" | "unknown";

export const STATUS_CHIP: Record<StatusState, { label: string; color: string; variant: "light" | "outline" }> = {
  up: { label: "Up", color: "green", variant: "light" },
  degraded: { label: "Degraded", color: "yellow", variant: "light" },
  down: { label: "Down", color: "red", variant: "light" },
  off: { label: "Off", color: "gray", variant: "light" },
  unknown: { label: "Unknown", color: "gray", variant: "outline" },
};

/** What a backend target's circuit state means to an operator. */
export function circuitState(circuit: string | undefined | null): { state: StatusState; label: string } {
  switch ((circuit ?? "").toLowerCase()) {
    case "closed":
      return { state: "up", label: "Up" };
    case "half-open":
    case "half_open":
    case "halfopen":
      return { state: "degraded", label: "Recovering" };
    case "open":
      return { state: "down", label: "Down" };
    case "standby":
    case "disabled":
      return { state: "off", label: "Standby" };
    default:
      return { state: "unknown", label: "Unknown" };
  }
}

/** One phrase for a WAF that logs and does not block, wherever it appears. */
export function wafModeState(mode: string | undefined | null): { state: StatusState; label: string } {
  switch (mode) {
    case "enforce":
    case "enforcing":
    case "block":
      return { state: "up", label: "Enforcing" };
    case "detect":
    case "detection":
    case "audit_only":
    case "no_categories":
      return { state: "degraded", label: "Audit only" };
    case "off":
    case "disabled":
      return { state: "off", label: "Off" };
    default:
      return { state: "unknown", label: "Unknown" };
  }
}

/**
 * A count against a total: all up is Up, none is Down, some is Degraded, and
 * a total the gateway did not compute is Unknown rather than "0 of 0".
 */
export function ratioState(up: number | undefined, total: number | undefined): { state: StatusState; label: string } {
  if (total === undefined || up === undefined || !Number.isFinite(total) || !Number.isFinite(up)) {
    return { state: "unknown", label: "Unknown" };
  }
  if (total === 0) return { state: "off", label: "None" };
  if (up >= total) return { state: "up", label: `${total} of ${total}` };
  if (up === 0) return { state: "down", label: `0 of ${total}` };
  return { state: "degraded", label: `${up} of ${total}` };
}
