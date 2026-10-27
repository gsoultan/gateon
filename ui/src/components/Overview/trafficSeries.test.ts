// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { asTrafficRange, trafficSeries } from "./trafficSeries";

const NOW = 1_800_000_000_000;
const MIN = 60_000;

describe("trafficSeries", () => {
  test("the last hour comes from the session and carries errors", () => {
    const s = trafficSeries(
      "1h",
      [
        { ts: NOW - 90 * MIN, requestsPerSecond: 9, errorsPerSecond: 1 },
        { ts: NOW - 10 * MIN, requestsPerSecond: 4, errorsPerSecond: 0.5 },
      ],
      [{ ts: NOW - 5 * MIN, requests: 36000, bytes: 0 }],
      NOW,
    );
    expect(s.requests).toEqual([{ ts: NOW - 10 * MIN, value: 4 }]);
    expect(s.errors).toEqual([{ ts: NOW - 10 * MIN, value: 0.5 }]);
    expect(s.note).toBeUndefined();
  });

  test("longer ranges come from hourly buckets as requests per second, without errors", () => {
    const s = trafficSeries(
      "24h",
      [{ ts: NOW - MIN, requestsPerSecond: 100, errorsPerSecond: 3 }],
      [
        { ts: NOW - 30 * 60 * MIN, requests: 1, bytes: 0 },
        { ts: NOW - 2 * 60 * MIN, requests: 7200, bytes: 0 },
      ],
      NOW,
    );
    expect(s.requests).toEqual([{ ts: NOW - 2 * 60 * MIN, value: 2 }]);
    expect(s.errors).toEqual([]);
    expect(s.note).toMatch(/last hour/);
  });

  test("an unknown range is the last hour", () => {
    expect(asTrafficRange("1y")).toBe("1h");
    expect(asTrafficRange("7d")).toBe("7d");
  });
});
