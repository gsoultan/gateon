// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { honoursWeights } from "./canaryPolicy";

describe("honoursWeights", () => {
  // The gateway refuses a canary, and refuses differing target weights at
  // save, on any other policy; the dashboard says so before the operator fills
  // the form in.
  test("round robin and weighted round robin, in any spelling", () => {
    for (const p of [undefined, "", "round_robin", "roundRobin", "weighted_round_robin", "weightedRoundRobin", "WRR"]) {
      expect(honoursWeights(p)).toBe(true);
    }
    for (const p of ["least_conn", "leastConn", "ai_predictive", "intelligent"]) {
      expect(honoursWeights(p)).toBe(false);
    }
  });
});
