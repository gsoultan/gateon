// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// The gateway-wide WAF's attack-family switches (WafConfig.categories, ADR
// 0064). Each is a tri-state: unset runs the family as the WAF tier decides --
// what every install upgraded from v1.1.0 has -- true runs it even where the
// tier would not, false removes the rules filed under it.

import type { WafCategories, WafConfig } from "../types/gateon";

export type WafFamilyKey = keyof WafCategories;

export interface WafFamily {
  /** The field of WafCategories, as the gateway's JSON spells it. */
  key: WafFamilyKey;
  /** The key GET /v1/waf/effective reports the family under. */
  effectiveKey: string;
  label: string;
}

export const GLOBAL_WAF_FAMILIES: WafFamily[] = [
  { key: "sqli", effectiveKey: "sqli", label: "SQL Injection" },
  { key: "xss", effectiveKey: "xss", label: "Cross-Site Scripting" },
  { key: "lfi", effectiveKey: "lfi", label: "File Inclusion & Traversal" },
  { key: "rce", effectiveKey: "rce", label: "Code Execution" },
  { key: "php", effectiveKey: "php", label: "PHP" },
  { key: "java", effectiveKey: "java", label: "Java" },
  { key: "nodejs", effectiveKey: "nodejs", label: "Node.js" },
  { key: "scanner", effectiveKey: "scanner", label: "Scanner Detection" },
  { key: "protocol", effectiveKey: "protocol", label: "Protocol Enforcement" },
  { key: "ransomwareDetection", effectiveKey: "ransomware_detection", label: "Ransomware" },
];

/** Whether the family's switch is on: anything but an explicit false. */
export function familySwitchOn(waf: WafConfig | undefined, key: WafFamilyKey): boolean {
  return waf?.categories?.[key] !== false;
}

/**
 * waf with the family's switch set explicitly: true runs it whatever the
 * tier says, false removes it. The other switches, set or unset, are kept.
 */
export function withFamily(waf: WafConfig, key: WafFamilyKey, on: boolean): WafConfig {
  return { ...waf, categories: { ...(waf.categories ?? {}), [key]: on } };
}

/** The labels of the families switched off explicitly. */
export function familiesOff(waf: WafConfig | undefined): string[] {
  return GLOBAL_WAF_FAMILIES.filter((f) => waf?.categories?.[f.key] === false).map((f) => f.label);
}
