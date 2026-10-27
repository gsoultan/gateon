// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { SETTINGS_INDEX, searchSettings } from "./settingsIndex";
import { SETTINGS_TABS } from "./tabs/settingsTab";

describe("settings index", () => {
  test("every entry belongs to a section that exists and ids are unique", () => {
    for (const e of SETTINGS_INDEX) expect(SETTINGS_TABS).toContain(e.section);
    expect(new Set(SETTINGS_INDEX.map((e) => e.id)).size).toBe(SETTINGS_INDEX.length);
  });

  test("finds a card by a word that is not in its title", () => {
    expect(searchSettings("clamav").map((e) => e.id)).toEqual(["malware"]);
    expect(searchSettings("retention").map((e) => e.section)).toContain("storage");
  });

  test("every word must match, and an empty query finds nothing", () => {
    expect(searchSettings("redis cluster")).toHaveLength(1);
    expect(searchSettings("redis clamav")).toHaveLength(0);
    expect(searchSettings("  ")).toHaveLength(0);
  });
});
