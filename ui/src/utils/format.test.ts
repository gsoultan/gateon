// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { formatLiftsIn, formatUptime, msUntilLiftsInChanges } from "./format";

// A kernel throttle's expiry used to be only in its description, as prose. The
// mitigation list now counts down to the structured expires_at.
describe("formatLiftsIn", () => {
  const now = Date.parse("2026-09-27T14:00:00Z");
  const at = (ms: number) => new Date(now + ms).toISOString();

  test("says how long until a limit lifts, never sooner than it does", () => {
    expect(formatLiftsIn(at(4 * 60_000 - 5_000), now)).toBe("lifts in 4m");
    expect(formatLiftsIn(at(4 * 60_000 + 10_000), now)).toBe("lifts in 5m");
    expect(formatLiftsIn(at(45_300), now)).toBe("lifts in 46s");
    expect(formatLiftsIn(at(60_000), now)).toBe("lifts in 60s");
    expect(formatLiftsIn(at(65 * 60_000), now)).toBe("lifts in 1h 5m");
    expect(formatLiftsIn(at(60 * 60_000), now)).toBe("lifts in 1h");
  });

  test("says lifting now once the moment has passed", () => {
    expect(formatLiftsIn(at(0), now)).toBe("lifting now");
    expect(formatLiftsIn(at(-30_000), now)).toBe("lifting now");
  });

  test("says nothing without an expiry it can read", () => {
    expect(formatLiftsIn(undefined, now)).toBe("");
    expect(formatLiftsIn("", now)).toBe("");
    expect(formatLiftsIn("soon", now)).toBe("");
  });
});

// The countdown wakes when its text would change rather than on an interval.
describe("msUntilLiftsInChanges", () => {
  const now = Date.parse("2026-09-27T14:00:00Z");
  const at = (ms: number) => new Date(now + ms).toISOString();

  test("wakes at the next minute while minutes are shown", () => {
    expect(msUntilLiftsInChanges(at(90_000), now)).toBe(30_000);
    expect(msUntilLiftsInChanges(at(120_000), now)).toBe(60_000);
    expect(msUntilLiftsInChanges(at(65 * 60_000 + 1_500), now)).toBe(1_500);
  });

  test("wakes every second through the last minute", () => {
    expect(msUntilLiftsInChanges(at(45_300), now)).toBe(300);
    expect(msUntilLiftsInChanges(at(45_000), now)).toBe(1_000);
    expect(msUntilLiftsInChanges(at(60_000), now)).toBe(1_000);
  });

  test("each wake-up lands where the text changes", () => {
    for (const rem of [45_300, 60_000, 90_000, 119_999, 3_600_001]) {
      const wait = msUntilLiftsInChanges(at(rem), now)!;
      const before = formatLiftsIn(at(rem), now + wait - 1);
      const after = formatLiftsIn(at(rem), now + wait);
      expect(before).not.toBe(after);
    }
  });

  test("never wakes once lifted, or without an expiry", () => {
    expect(msUntilLiftsInChanges(at(0), now)).toBeNull();
    expect(msUntilLiftsInChanges(at(-1), now)).toBeNull();
    expect(msUntilLiftsInChanges(undefined, now)).toBeNull();
    expect(msUntilLiftsInChanges("soon", now)).toBeNull();
  });
});

describe("formatUptime", () => {
  // The live snapshot reports uptime as float seconds, and the status card
  // printed the fraction as it came: "50.395464208s", "3m 5.900000000000006s".
  test("shows whole seconds under an hour", () => {
    expect(formatUptime(50.395464208)).toBe("50s");
    expect(formatUptime(185.9)).toBe("3m 5s");
  });

  test("shows hours and minutes from an hour on", () => {
    expect(formatUptime(3725.2)).toBe("1h 2m");
  });
});
