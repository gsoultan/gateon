// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { StatusState } from "../status/statusState";
import type { RouteProblem } from "../../hooks/useRouteProblems";
import type { SecurityPosture } from "../../hooks/useSecurityPosture";
import type { StatusResponse, TargetStats } from "../../types/gateon";
import type { TLSCertMetric } from "../../types/metrics";

/** Where a row's one action leads. */
export interface AttentionAction {
  label: string;
  to: string;
  search?: Record<string, string>;
}

/** One row of the Overview's Needs attention list. */
export interface AttentionItem {
  id: string;
  state: StatusState;
  title: string;
  detail: string;
  action: AttentionAction;
}

export interface OnboardingCounts {
  listeners: number;
  services: number;
  routes: number;
  protected: boolean;
}

export interface AttentionInputs {
  routeStats?: Record<string, TargetStats[]>;
  routeProblems?: Map<string, RouteProblem>;
  posture?: SecurityPosture;
  certificates?: TLSCertMetric[] | null;
  status?: StatusResponse;
  onboarding?: OnboardingCounts;
}

/** The list never grows past this; the pages it links to hold the rest. */
export const ATTENTION_CAP = 20;
/** A certificate this close to expiry is a row. */
export const CERT_WARN_DAYS = 30;
/** A resource this full is a red row, the same bar the Resources card turns red at. */
export const RESOURCE_RED_PERCENT = 90;

/**
 * The Certificates card's answer, from the metrics snapshot.
 *
 * Unknown only while no snapshot has arrived. The gateway omits an empty
 * `tlsCertificates` (the field is `omitzero`), so a gateway serving no
 * certificate sends none at all; reading the missing field as "not yet known"
 * kept the card on "Waiting for metrics" forever on every plain-HTTP install.
 */
export function certificateHealth(
  snapshot: { tlsCertificates?: TLSCertMetric[] | null } | undefined,
): { state: StatusState; label: string; detail: string } {
  if (snapshot === undefined) return { state: "unknown", label: "Unknown", detail: "Waiting for metrics" };
  const certs = snapshot.tlsCertificates ?? [];
  if (certs.length === 0) return { state: "off", label: "None", detail: "No certificate is served" };
  const soonest = Math.min(...certs.map((c) => c.daysRemaining));
  if (soonest <= 0) return { state: "down", label: "Expired", detail: "A certificate has expired" };
  if (soonest < CERT_WARN_DAYS) return { state: "degraded", label: `${soonest}d`, detail: `Soonest expiry in ${soonest} days` };
  return { state: "up", label: "Up", detail: `${certs.length} valid, soonest expiry in ${soonest} days` };
}

const STATE_RANK: Record<StatusState, number> = { down: 0, degraded: 1, unknown: 2, off: 3, up: 4 };

function targetRows(stats: Record<string, TargetStats[]>): AttentionItem[] {
  const rows: AttentionItem[] = [];
  for (const [routeId, targets] of Object.entries(stats)) {
    for (const t of targets ?? []) {
      const open = t.circuitState === "open";
      if (t.alive && !open) continue;
      rows.push({
        id: `target:${routeId}:${t.url}`,
        state: "down",
        title: open ? "Backend circuit open" : "Backend unhealthy",
        detail: `${t.url} on route ${routeId}${open ? " is not receiving traffic" : " failed its health check"}`,
        action: { label: "View service", to: "/services" },
      });
    }
  }
  return rows;
}

function routeProblemRows(problems: Map<string, RouteProblem>): AttentionItem[] {
  return [...problems.values()].map((p) => ({
    id: `route:${p.routeId}`,
    state: p.kind === "middleware_off" ? "degraded" : "down",
    title:
      p.kind === "refuses"
        ? "Route refuses every request"
        : p.kind === "matches_nothing"
          ? "Route matches nothing"
          : "Route runs without a policy",
    detail: `${p.route}: ${p.reason}`,
    action: { label: "Open route", to: "/routes", search: { q: p.route } },
  }));
}

function postureRows(posture: SecurityPosture): AttentionItem[] {
  const rows: AttentionItem[] = [];
  const mode = posture.waf?.mode;
  if (posture.waf?.enabled && (mode === "detect" || mode === "no_categories")) {
    rows.push({
      id: "waf:audit-only",
      state: "degraded",
      title: mode === "detect" ? "WAF is audit only" : "WAF has every attack family off",
      detail: "Attacks are recorded and forwarded, not blocked.",
      action: { label: "Review WAF", to: "/settings", search: { tab: "security" } },
    });
  }
  const unprotected = posture.waf?.routes?.unprotected ?? 0;
  if (unprotected > 0) {
    rows.push({
      id: "waf:unprotected",
      state: "degraded",
      title: `${unprotected} ${unprotected === 1 ? "route is" : "routes are"} unprotected`,
      detail: "No WAF inspects their traffic.",
      action: { label: "View routes", to: "/routes" },
    });
  }
  if (posture.clamav?.enabled && posture.clamav.lastError) {
    rows.push({
      id: "clamav:error",
      state: "degraded",
      title: "Malware scanner reported an error",
      detail: posture.clamav.lastError,
      action: { label: "Open security", to: "/security" },
    });
  }
  return rows;
}

function certificateRows(certs: TLSCertMetric[]): AttentionItem[] {
  return certs
    .filter((c) => c.daysRemaining < CERT_WARN_DAYS)
    .map((c) => ({
      id: `cert:${c.certName}:${c.domain}`,
      state: c.daysRemaining <= 0 ? "down" : "degraded",
      title: c.daysRemaining <= 0 ? "Certificate expired" : `Certificate expires in ${c.daysRemaining} ${c.daysRemaining === 1 ? "day" : "days"}`,
      detail: `${c.certName} for ${c.domain}`,
      action: { label: "Open TLS", to: "/tls" },
    }));
}

function resourceRows(status: StatusResponse): AttentionItem[] {
  const rows: AttentionItem[] = [];
  const gauges: Array<[string, number | undefined, string]> = [
    ["cpu", status.cpuUsage, "CPU"],
    ["memory", status.memoryUsagePercent, "Memory"],
    ["disk", status.storageUsagePercent, "Disk"],
  ];
  for (const [key, value, label] of gauges) {
    if (value === undefined || value < RESOURCE_RED_PERCENT) continue;
    rows.push({
      id: `resource:${key}`,
      state: "down",
      title: `${label} at ${Math.round(value)}%`,
      detail: `Above ${RESOURCE_RED_PERCENT}% of what the gateway can use.`,
      action: { label: "Open diagnostics", to: "/diagnostics" },
    });
  }
  return rows;
}

function onboardingRows(counts: OnboardingCounts): AttentionItem[] {
  const rows: AttentionItem[] = [];
  if (counts.listeners === 0) {
    rows.push({
      id: "setup:listener",
      state: "unknown",
      title: "Create a listener",
      detail: "The gateway accepts no connections until it has an address and port.",
      action: { label: "Create listener", to: "/listeners" },
    });
  }
  if (counts.services === 0) {
    rows.push({
      id: "setup:service",
      state: "unknown",
      title: "Add a service",
      detail: "The backends traffic is sent to.",
      action: { label: "Add service", to: "/services" },
    });
  }
  if (counts.routes === 0) {
    rows.push({
      id: "setup:route",
      state: "unknown",
      title: "Add a route",
      detail: "What to match, and which service to send it to.",
      action: { label: "Add route", to: "/routes" },
    });
  }
  if (!counts.protected && counts.routes > 0) {
    rows.push({
      id: "setup:protect",
      state: "unknown",
      title: "Protect a route",
      detail: "No route carries the WAF or another security policy yet.",
      action: { label: "Add policy", to: "/policies" },
    });
  }
  return rows;
}

/**
 * The Needs attention list, from what the Overview already fetches. Worst
 * first, then in the order the inputs name them, cut at ATTENTION_CAP. Pure
 * so the ordering and the thresholds can be tested without a query client.
 */
export function deriveAttention(inputs: AttentionInputs): AttentionItem[] {
  const rows: AttentionItem[] = [];
  if (inputs.routeStats) rows.push(...targetRows(inputs.routeStats));
  if (inputs.routeProblems) rows.push(...routeProblemRows(inputs.routeProblems));
  if (inputs.certificates) rows.push(...certificateRows(inputs.certificates));
  if (inputs.status) rows.push(...resourceRows(inputs.status));
  if (inputs.posture) rows.push(...postureRows(inputs.posture));
  if (inputs.onboarding) rows.push(...onboardingRows(inputs.onboarding));
  return rows
    .map((row, index) => ({ row, index }))
    .sort((a, b) => STATE_RANK[a.row.state] - STATE_RANK[b.row.state] || a.index - b.index)
    .map(({ row }) => row)
    .slice(0, ATTENTION_CAP);
}
