// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { ListRoutesResponse, Route } from "../types/gateon";

// withRouteDisabled sets one route's `disabled` in a cached ["routes", ...]
// query, which holds one of two shapes: a page of the routes list, or the
// topology view's plain array of every route. Anything else is returned as is.
//
// The optimistic pause update was written for the page shape alone, so with
// the topology view cached it read `routes` off an array, threw, and the pause
// never ran.
export function withRouteDisabled<T extends ListRoutesResponse | Route[] | undefined>(
  current: T,
  routeId: string,
  disabled: boolean,
): T {
  const flip = (routes: Route[]) => routes.map((r) => (r.id === routeId ? { ...r, disabled } : r));
  if (Array.isArray(current)) {
    return flip(current) as T;
  }
  if (current && Array.isArray(current.routes)) {
    return { ...current, routes: flip(current.routes) } as T;
  }
  return current;
}
