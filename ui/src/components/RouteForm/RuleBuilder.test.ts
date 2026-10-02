// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { expect, test } from "bun:test";
import { conditionsToRule, parseRuleToConditions } from "./RuleBuilder";

// The gateway reads a rule value literally, with no escapes (ADR 0043). The
// builder used to escape backslashes, so a regex such as \d+ became \\d+ --
// a literal backslash to the gateway -- and doubled again on every save.
test("a regex with backslashes is saved as written and survives a re-save", () => {
  const rule = "Host(`api.example.com`) && PathRegex(`^/api/v\\d+/`)";
  const once = conditionsToRule(parseRuleToConditions(rule));
  expect(once).toBe(rule);
  expect(conditionsToRule(parseRuleToConditions(once))).toBe(rule);
});

test("a condition typed into the builder is written literally", () => {
  const rule = conditionsToRule([
    { id: "a", type: "PathRegex", value: "^/v\\d+\\.json$", combineWithNext: "and" },
    { id: "b", type: "PathPrefix", value: "/v1", combineWithNext: "and" },
  ]);
  expect(rule).toBe("PathRegex(`^/v\\d+\\.json$`) && PathPrefix(`/v1`)");
});
