// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { nextRouteHistory } from "./routeStatsHistory";

describe("nextRouteHistory", () => {
  test("the first poll adds no point, not the route's lifetime total", () => {
    expect(nextRouteHistory([], null, 50_000)).toEqual([]);
  });

  test("later polls add the requests since the previous one", () => {
    let h = nextRouteHistory([], null, 50_000);
    h = nextRouteHistory(h, 50_000, 50_040);
    h = nextRouteHistory(h, 50_040, 50_100);
    expect(h).toEqual([40, 60]);
  });

  test("a counter that went backwards adds zero", () => {
    expect(nextRouteHistory([5], 900, 10)).toEqual([5, 0]);
  });

  test("keeps the last twelve points", () => {
    let h: number[] = [];
    let prev: number | null = null;
    for (let total = 0; total <= 2000; total += 100) {
      h = nextRouteHistory(h, prev, total);
      prev = total;
    }
    expect(h).toHaveLength(12);
  });
});
