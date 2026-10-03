// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

/** What a WAF does with a match. "audit_only" records and blocks nothing. */
export type WafMode = "enforcing" | "audit_only" | "off";

/**
 * What a WAF runs, from GET /v1/waf/effective: read by the gateway from the
 * config its engine is built from, not from the stored switches. The global
 * WAF ignores its category switches (they cannot be told apart from "never
 * set"), so the stored values are not what runs (ADR 0044).
 */
export interface EffectiveWaf {
  mode: WafMode;
  paranoiaLevel: number;
  /** Switch key (sqli, xss, ..., malware_detection) -> whether its rules run. */
  categories: Record<string, boolean>;
}

export interface EffectiveWafView {
  global: EffectiveWaf;
  routeWafs: { id: string; name: string; effective: EffectiveWaf }[];
}

/**
 * The switches a route WAF defaults to on when no global WAF runs; the others
 * (malware, ransomware, DLP, behavioural reputation) default to off.
 */
const ROUTE_DEFAULT_ON = new Set([
  "sqli", "xss", "lfi", "rce", "php", "java", "nodejs", "scanner", "protocol", "wordpress",
]);

/**
 * Whether a route WAF switch is on, by the gateway's merge rule: a key the
 * route sets wins; a key it leaves out is what the global WAF runs, or the
 * route default when the global WAF is off.
 */
export function routeSwitchOn(
  config: Record<string, string>,
  key: string,
  global: EffectiveWaf | undefined,
): { on: boolean; inherited: boolean } {
  const set = config[key];
  if (set !== undefined && set.trim() !== "") {
    // As the gateway parses them: a category is off only when it says
    // "false"; the opt-in protections are on only when they say "true".
    const v = set.trim().toLowerCase();
    return { on: ROUTE_DEFAULT_ON.has(key) ? v !== "false" : v === "true", inherited: false };
  }
  if (global && global.mode !== "off") {
    return { on: global.categories[key] === true, inherited: true };
  }
  return { on: ROUTE_DEFAULT_ON.has(key), inherited: false };
}
