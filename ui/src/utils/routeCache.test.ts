// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import type { ListRoutesResponse, Route } from "../types/gateon";
import { withRouteDisabled } from "./routeCache";

const route = (id: string): Route => ({
  id,
  type: "http",
  entrypoints: [],
  rule: `Host(\`${id}.example\`)`,
  priority: 0,
  middlewares: [],
  serviceId: "svc",
});

describe("withRouteDisabled", () => {
  test("pauses the route in a page of the routes list", () => {
    const page: ListRoutesResponse = { routes: [route("a"), route("b")], totalCount: 2, page: 0, pageSize: 10 };
    const got = withRouteDisabled(page, "b", true);
    expect(got.routes.map((r) => r.disabled)).toEqual([undefined, true]);
    expect(got.totalCount).toBe(2);
  });

  // The topology view caches every route as a plain array under
  // ["routes", "all"]; the pause update threw on it.
  test("pauses the route in the topology view's array", () => {
    const got = withRouteDisabled([route("a"), route("b")], "a", true);
    expect(got.map((r) => r.disabled)).toEqual([true, undefined]);
  });

  test("leaves an empty cache entry alone", () => {
    expect(withRouteDisabled(undefined, "a", true)).toBeUndefined();
  });
});
