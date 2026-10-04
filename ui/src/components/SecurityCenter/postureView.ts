// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// What the Security Hub says about the gateway's protections, from the posture
// report. Pure functions, so every sentence an operator acts on is testable
// without rendering (ADR 0048).

import type { PostureScore, SignaturePosture, WafPosture } from "../../hooks/useSecurityPosture";
import type { Reputation } from "../../types/gateon";

export interface StatusView {
  label: string;
  color: string;
  detail: string;
}

/** The words the hub uses for a WAF that records attacks and forwards them. */
export const DETECTING_ONLY = "Detecting only (audit)";

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/**
 * The WAF card. It reads the mode of the WAF that inspects each route -- a
 * route with its own WAF middleware runs that one -- so an audit-only WAF,
 * global or per route, is never "Protecting all routes".
 */
export function wafStatus(waf: WafPosture): StatusView {
  const r = waf.routes;
  if (!r || r.total === 0) {
    switch (waf.mode) {
      case "enforce":
        return { label: "Blocking", color: "teal", detail: "The gateway-wide WAF blocks; no HTTP route yet." };
      case "detect":
        return { label: DETECTING_ONLY, color: "orange", detail: "The gateway-wide WAF records attacks and forwards them." };
      default:
        return { label: "Disabled", color: "gray", detail: "No WAF inspects requests." };
    }
  }
  const catsOff = r.categoriesOff ?? 0;
  const detail =
    `${r.enforcing} of ${r.total} routes blocking, ${r.detecting} detecting only (audit), ` +
    `${r.unprotected} with no WAF` +
    (catsOff > 0 ? `, ${catsOff} with every attack category off.` : ".");
  if (r.unprotected === r.total) return { label: "Disabled", color: "gray", detail };
  // A WAF with every attack category off runs but refuses none of them.
  if (r.enforcing === 0 && r.detecting === 0) return { label: "Not blocking attacks", color: "red", detail };
  if (r.enforcing === 0) return { label: DETECTING_ONLY, color: "orange", detail };
  if (r.enforcing === r.total) return { label: `Blocking on all ${plural(r.total, "route")}`, color: "teal", detail };
  return { label: `Blocking on ${r.enforcing} of ${plural(r.total, "route")}`, color: "yellow", detail };
}

/** True when some route's WAF only detects: the hub then says so up front. */
export function wafDetectsSomewhere(waf: WafPosture | undefined): boolean {
  if (!waf) return false;
  if (waf.routes?.total) return waf.routes.detecting > 0;
  return waf.mode === "detect";
}

/**
 * The signature engine card. The engine scans uploads only inside a File
 * Security middleware, so with no such route nothing is scanned, whatever
 * rules it holds.
 */
export function signatureStatus(sig: SignaturePosture): StatusView {
  if (!sig.enabled || sig.routes === 0) {
    return {
      label: "Not running",
      color: "gray",
      detail: "Signatures scan uploads only on routes with a File Security middleware; none has one.",
    };
  }
  return {
    label: `${plural(sig.ruleCount, "rule")} on ${plural(sig.routes, "route")}`,
    color: "blue",
    detail: "Uploads to these routes are scanned against the built-in signature rules.",
  };
}

/** The posture ring's colour for a percentage. */
export function postureColor(percent: number): string {
  if (percent > 85) return "teal";
  if (percent > 65) return "blue";
  if (percent > 40) return "orange";
  return "red";
}

/** The formula, as the tooltip states it before listing the controls. */
export const POSTURE_FORMULA =
  "Weighted sum of the protections in effect: full weight when a control blocks, half when it only " +
  "detects or covers part, none when off. Computed from configuration only: traffic and attackers do not move it.";

/** One line per control: "WAF 20/40 — 1 of 2 routes blocking, ...". */
export function postureLines(score: PostureScore): string[] {
  return score.controls.map(
    (c) => `${c.label}: ${Math.round(c.weight * c.credit)}/${c.weight} — ${c.detail}`,
  );
}

export interface ReputationView {
  value: string;
  detail: string;
}

/**
 * The reputation card, from the clients whose reputation is below perfect.
 * The list is capped server-side at `limit`, so a full list reads "N+".
 */
export function reputationSummary(reps: Reputation[], limit: number): ReputationView {
  const lowered = reps.filter((r) => (r.score ?? 100) < 100);
  if (lowered.length === 0) {
    return { value: "None lowered", detail: "No client has lost reputation; scores recover over time." };
  }
  const lowest = Math.min(...lowered.map((r) => r.score ?? 100));
  const count = reps.length >= limit ? `${lowered.length}+` : String(lowered.length);
  return {
    value: `${count} lowered`,
    detail: `Lowest score ${Math.round(lowest)}/100. Penalised by WAF and anomaly findings; recovers over time.`,
  };
}
