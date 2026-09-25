// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { honoursWeights } from "./canaryPolicy";

describe("honoursWeights", () => {
  // The gateway refuses a canary on any other policy (checkRunnable); the
  // wizard says so before the operator fills it in.
  test("only weighted round robin, in any spelling", () => {
    for (const p of ["weighted_round_robin", "weightedRoundRobin", "WRR"]) {
      expect(honoursWeights(p)).toBe(true);
    }
    for (const p of [undefined, "", "round_robin", "roundRobin", "least_conn", "ai_predictive"]) {
      expect(honoursWeights(p)).toBe(false);
    }
  });
});
