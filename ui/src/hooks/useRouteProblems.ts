// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";

/** A route that cannot serve as configured (GET /v1/routes/problems). */
export interface RouteProblem {
  routeId: string;
  route: string;
  /**
   * "refuses": every request is answered 503; "matches_nothing": its rule does not parse;
   * "middleware_off": it serves, without a middleware it names that was saved with a config
   * the gateway now refuses.
   */
  kind: "refuses" | "matches_nothing" | "middleware_off";
  reason: string;
}

export const ROUTE_PROBLEMS_QUERY_KEY = ["route-problems"];

/** The routes that refuse every request or match none, by route ID. */
export function useRouteProblems() {
  return useQuery<Map<string, RouteProblem>>({
    queryKey: ROUTE_PROBLEMS_QUERY_KEY,
    queryFn: async () => {
      const res = await apiFetch("/v1/routes/problems");
      if (!res.ok) throw new Error("Failed to fetch route problems");
      const list: RouteProblem[] = await res.json();
      return new Map(list.map((p) => [p.routeId, p]));
    },
    refetchInterval: 30000,
  });
}
