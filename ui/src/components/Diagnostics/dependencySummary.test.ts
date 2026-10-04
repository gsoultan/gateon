// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { dependencySummary } from "./dependencySummary";

// Truth T41: the Infrastructure Dependencies card said "All checks active", a
// string literal, beside dependencies the same card showed as Degraded.
describe("the dependency summary badge", () => {
  test("names the degraded dependencies instead of a constant", () => {
    const s = dependencySummary([{ healthy: true }, { healthy: false }]);
    expect(s.label).toBe("1 of 2 degraded");
    expect(s.color).toBe("red");
  });
  test("says all are healthy only when each is", () => {
    expect(dependencySummary([{ healthy: true }, { healthy: true }])).toEqual({ label: "All 2 healthy", color: "teal" });
  });
  test("says when nothing is reported", () => {
    expect(dependencySummary([]).label).toBe("No checks reported");
  });
});
