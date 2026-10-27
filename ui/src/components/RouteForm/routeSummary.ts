// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { Route } from "../../types/gateon";

export interface RouteSummaryLookups {
  listenerNames: Map<string, string>;
  serviceNames: Map<string, string>;
  policyNames: Map<string, string>;
}

const list = (names: string[], noun: string): string => {
  if (names.length === 0) return `no ${noun}`;
  if (names.length <= 3) return names.join(", ");
  return `${names.slice(0, 2).join(", ")} and ${names.length - 2} more`;
};

/**
 * The route as one sentence: what it matches, on which listeners, where it
 * sends traffic and what protects it. Read at the top of the editor so a
 * change to any field is read back in words before it is saved.
 */
export function summarizeRoute(values: Route, lookups: RouteSummaryLookups): string {
  const isL4 = values.type === "tcp" || values.type === "udp";
  const match = isL4 ? `Every ${values.type.toUpperCase()} connection` : values.rule ? `Requests matching ${values.rule}` : "Requests matching (no rule yet)";
  const listeners = list((values.entrypoints ?? []).map((id) => lookups.listenerNames.get(id) ?? id), "listener");
  const service = values.serviceId ? (lookups.serviceNames.get(values.serviceId) ?? values.serviceId) : "no service yet";
  const policies = (values.middlewares ?? []).map((id) => lookups.policyNames.get(id) ?? id);
  const protection = policies.length === 0 ? "with no policy" : `protected by ${list(policies, "policy")}`;
  const state = values.disabled ? " This route is disabled." : "";
  return `${match} on ${listeners} go to ${service}, ${protection}.${state}`;
}
