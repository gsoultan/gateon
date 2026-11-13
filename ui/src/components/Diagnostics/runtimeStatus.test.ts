// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { governorBadge, predictorBadge } from "./runtimeStatus";

const governor = {
  active: true,
  sampled: true,
  readingsUnavailable: false,
  underPressure: false,
  memoryHooksCount: 2,
  cpuHooksCount: 1,
  memoryPressurePercent: 40,
  cpuPressurePercent: 10,
  memoryThresholdPercent: 80,
  cpuThresholdPercent: 90,
  memoryYardstick: "host memory",
};

// The badge was `active ? "STABLE" : "OFF"`, and active was always true.
describe("the resource governor badge", () => {
  test("is STABLE only when the loop runs, has read, and is below its thresholds", () => {
    expect(governorBadge(governor).label).toBe("STABLE");
  });
  test("says so when the gateway is under pressure", () => {
    const b = governorBadge({ ...governor, underPressure: true, memoryPressurePercent: 95 });
    expect(b.label).toBe("UNDER PRESSURE");
    expect(b.color).toBe("red");
  });
  test("does not read a failed reading as no pressure", () => {
    expect(governorBadge({ ...governor, readingsUnavailable: true }).label).toBe("NO READING");
  });
  test("is OFF when the loop is not running, or there is no governor", () => {
    expect(governorBadge({ ...governor, active: false }).label).toBe("OFF");
    expect(governorBadge(undefined).label).toBe("OFF");
  });
  test("does not call zeros nobody measured stable", () => {
    expect(governorBadge({ ...governor, sampled: false }).label).toBe("STARTING");
  });
});

// The badge was ON whenever a model was loaded, which is always.
describe("the predictive AI badge", () => {
  test("says it is not in use when no service has the policy", () => {
    expect(predictorBadge({ aiPredictorEnabled: true, aiPolicyServiceCount: 0 }).label).toBe("NOT IN USE");
  });
  test("counts the services it balances", () => {
    const b = predictorBadge({ aiPredictorEnabled: true, aiPolicyServiceCount: 2 });
    expect(b.label).toBe("IN USE");
    expect(b.detail).toBe("Balancing 2 services");
    expect(predictorBadge({ aiPredictorEnabled: true, aiPolicyServiceCount: 1 }).detail).toBe("Balancing 1 service");
  });
  test("is OFF when no model loaded", () => {
    expect(predictorBadge({ aiPredictorEnabled: false, aiPolicyServiceCount: 3 }).label).toBe("OFF");
  });
});
