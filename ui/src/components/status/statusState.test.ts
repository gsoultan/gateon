// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { STATUS_CHIP, circuitState, ratioState, wafModeState } from "./statusState";

describe("the status vocabulary", () => {
  test("has exactly five states, each with text next to its colour", () => {
    expect(Object.keys(STATUS_CHIP).sort()).toEqual(["degraded", "down", "off", "unknown", "up"]);
    for (const chip of Object.values(STATUS_CHIP)) expect(chip.label.length).toBeGreaterThan(0);
  });

  test("never shows CLOSED or HALF-OPEN for a circuit", () => {
    expect(circuitState("closed")).toEqual({ state: "up", label: "Up" });
    expect(circuitState("half-open")).toEqual({ state: "degraded", label: "Recovering" });
    expect(circuitState("open")).toEqual({ state: "down", label: "Down" });
    expect(circuitState(undefined).state).toBe("unknown");
  });

  test("calls a WAF that does not block Audit only, whatever the API calls it", () => {
    expect(wafModeState("detect").label).toBe("Audit only");
    expect(wafModeState("audit_only").label).toBe("Audit only");
    expect(wafModeState("no_categories").label).toBe("Audit only");
    expect(wafModeState("enforce")).toEqual({ state: "up", label: "Enforcing" });
    expect(wafModeState("off").state).toBe("off");
  });

  test("shows Unknown, not 0 of 0, when a total was not computed", () => {
    expect(ratioState(undefined, undefined).state).toBe("unknown");
    expect(ratioState(3, 3)).toEqual({ state: "up", label: "3 of 3" });
    expect(ratioState(2, 3)).toEqual({ state: "degraded", label: "2 of 3" });
    expect(ratioState(0, 3)).toEqual({ state: "down", label: "0 of 3" });
    expect(ratioState(0, 0).state).toBe("off");
  });
});
