// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { MIDDLEWARE_TYPES, POLICY_FAMILIES, policyType } from "./middlewareTypes";

describe("the policy catalog", () => {
  test("every type sits on one of the six shelves and says what it does", () => {
    for (const t of MIDDLEWARE_TYPES) {
      expect(POLICY_FAMILIES).toContain(t.group);
      expect(t.description.length).toBeGreaterThan(10);
    }
    expect(new Set(MIDDLEWARE_TYPES.map((t) => t.group)).size).toBe(POLICY_FAMILIES.length);
  });

  test("looks a type up by the value the API uses", () => {
    expect(policyType("waf")?.group).toBe("Protection");
    expect(policyType("no_such_type")).toBeUndefined();
  });
});
