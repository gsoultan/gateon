// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { Middleware } from "../../types/gateon";

export interface PolicyOption {
  value: string;
  label: string;
}

/**
 * The policies a route of this type can be given.
 *
 * A TCP route (SSH, RDP, raw TCP) enforces only an IP filter, against the
 * connection's peer address; a UDP route enforces none. The picker used to
 * offer every middleware on every route, so an SSH route could be saved with
 * a WAF or authentication attached that nothing would ever run. A policy
 * already on the route stays listed, marked, so it can be seen and removed
 * rather than kept invisibly.
 */
export function policyOptions(middlewares: Middleware[], routeType: string, selected: string[]): PolicyOption[] {
  const isL4 = routeType === "tcp" || routeType === "udp";
  const out: PolicyOption[] = [];
  for (const mw of middlewares) {
    const applies = !isL4 || (routeType === "tcp" && mw.type === "ipfilter");
    if (applies) {
      out.push({ value: mw.id, label: `${mw.name} (${mw.type})` });
    } else if (selected.includes(mw.id)) {
      out.push({ value: mw.id, label: `${mw.name} (${mw.type}, not applied to ${routeType.toUpperCase()} routes)` });
    }
  }
  return out;
}

/** What the policy picker says it does for a route of this type. */
export function policyDescription(routeType: string): string {
  if (routeType === "tcp") return "Only IP filters apply to a TCP route: they decide which client addresses may open a connection";
  if (routeType === "udp") return "No policy is applied to a UDP route";
  return "Add a protection preset above or pick the policies this route is protected by";
}
