// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { TARPIT_MAX_DELAY_REQUIRED, TARPIT_THRESHOLD_REQUIRED, tarpitProblem } from "./middlewareConfigProblems";

/**
 * The gateway's save check (CheckTarpitSave) reads the same file in its own
 * test, so the form and the gateway refuse the same tarpits with the same
 * words. The form refused a tarpit without a threshold above 0 (ADR 0063)
 * while the gateway saved it from the API or an import.
 */
interface TarpitSaveFixture {
  messages: Record<"threshold" | "max_delay", string>;
  cases: { name: string; config: Record<string, string>; refused: "" | "threshold" | "max_delay" }[];
}

const fixture: TarpitSaveFixture = JSON.parse(
  readFileSync(new URL("../../../../internal/middleware/security/testdata/tarpit_save.json", import.meta.url), "utf8"),
);

describe("the tarpit save rule the gateway shares", () => {
  test("says what the gateway says", () => {
    expect(TARPIT_THRESHOLD_REQUIRED).toBe(fixture.messages.threshold);
    expect(TARPIT_MAX_DELAY_REQUIRED).toBe(fixture.messages.max_delay);
  });

  test("refuses exactly the configs the gateway refuses", () => {
    expect(fixture.cases.length).toBeGreaterThanOrEqual(10);
    for (const c of fixture.cases) {
      const want = c.refused ? fixture.messages[c.refused] : undefined;
      expect({ name: c.name, problem: tarpitProblem(c.config) }).toEqual({ name: c.name, problem: want });
    }
  });
});
