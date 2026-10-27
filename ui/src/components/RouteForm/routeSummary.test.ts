// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { summarizeRoute } from "./routeSummary";
import type { Route } from "../../types/gateon";

const lookups = {
  listenerNames: new Map([["ep1", "web :443"]]),
  serviceNames: new Map([["svc", "shop-api"]]),
  policyNames: new Map([["mw1", "WAF"], ["mw2", "Rate limit"]]),
};
const route = (over: Partial<Route>): Route =>
  ({ id: "", name: "", type: "http", rule: "", priority: 0, entrypoints: [], middlewares: [], serviceId: "", disabled: false, ...over }) as Route;

describe("summarizeRoute", () => {
  test("reads a complete route back in one sentence", () => {
    expect(summarizeRoute(route({ rule: "Host(`shop.example`)", entrypoints: ["ep1"], serviceId: "svc", middlewares: ["mw1", "mw2"] }), lookups)).toBe(
      "Requests matching Host(`shop.example`) on web :443 go to shop-api, protected by WAF, Rate limit.",
    );
  });

  test("names what is still missing instead of hiding it", () => {
    expect(summarizeRoute(route({}), lookups)).toBe("Requests matching (no rule yet) on no listener go to no service yet, with no policy.");
  });

  test("a TCP route has no rule, and a disabled route says so", () => {
    expect(summarizeRoute(route({ type: "tcp", entrypoints: ["ep1"], serviceId: "svc", disabled: true }), lookups)).toBe(
      "Every TCP connection on web :443 go to shop-api, with no policy. This route is disabled.",
    );
  });

  test("an id the lookups do not know is shown as the id", () => {
    expect(summarizeRoute(route({ rule: "Path(`/`)", entrypoints: ["ghost"], serviceId: "svc" }), lookups)).toContain("on ghost go to");
  });
});
