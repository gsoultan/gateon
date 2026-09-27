// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { mapEmptyMessage } from "./anomalyMapMessages";

// Geo lookups are local-only: with no MaxMind database every finding is
// "XX". The map said "No geo-tagged anomalies detected" over a list of
// findings, which read as "nothing is wrong".
describe("mapEmptyMessage", () => {
  test("says there is nothing when there is nothing", () => {
    expect(mapEmptyMessage(0)).toBe("No anomalies detected");
  });
  test("says findings exist but have no location, and where locations come from", () => {
    expect(mapEmptyMessage(3)).toBe(
      "3 findings have no location. Locations need a local MaxMind GeoLite2 database (Settings → GeoIP).",
    );
    expect(mapEmptyMessage(1)).toContain("1 finding has no location");
  });
});
