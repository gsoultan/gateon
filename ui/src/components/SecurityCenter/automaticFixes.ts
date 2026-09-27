// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { Anomaly } from "../../types/gateon";

/**
 * The finding types the gateway can apply a fix for: the keys of
 * recommendationFixes in internal/api/diagnostics_api.go. A Go test reads this
 * list and fails when the two differ, so keep it one quoted type per line.
 *
 * "Apply automatic fix" used to be offered on every finding. For nine of the
 * types the engine emits there is no fix, and the click could only answer that
 * nothing had been done.
 */
export const AUTOMATIC_FIX_TYPES: ReadonlySet<string> = new Set([
  "brute_force_attempt",
  "cors_violation",
  "geofence_violation",
  "high_traffic",
  "management_access_violation",
  "scanner",
  "security_block_recommendation",
  "security_scan",
  "security_threat",
  "security_vulnerability",
  "shadowed_route",
  "slow_client_anomaly",
  "sqli_detected",
  "unlisted_route",
  "waf_block",
  "waf_blocked",
  "waf_violation",
  "xss_detected",
]);

/** Whether the dashboard offers "Apply automatic fix" for this finding. */
export function offersAutomaticFix(anomaly: Pick<Anomaly, "type" | "mitigated">): boolean {
  return !anomaly.mitigated && AUTOMATIC_FIX_TYPES.has(anomaly.type);
}
