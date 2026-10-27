// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { isActivePath, navSections } from "./navigation";

const labels = (ctx: Parameters<typeof navSections>[0]) =>
  navSections(ctx).flatMap((s) => s.items.map((i) => i.label));

describe("the sidebar", () => {
  test("keeps a page highlighted on its own sub-paths", () => {
    // The sidebar compared the whole path, so a trace opened from Traces left
    // nothing highlighted.
    expect(isActivePath("/traces/abc", "/traces")).toBe(true);
    expect(isActivePath("/traces", "/traces")).toBe(true);
  });

  test("does not highlight a page whose name is only a prefix", () => {
    expect(isActivePath("/routes-archive", "/routes")).toBe(false);
  });

  test("highlights the Overview on the Overview only", () => {
    expect(isActivePath("/", "/")).toBe(true);
    expect(isActivePath("/routes", "/")).toBe(false);
  });

  test("lists Access for an administrator only", () => {
    expect(labels({ isAdmin: true })).toContain("Access");
    expect(labels({ isAdmin: false })).not.toContain("Access");
  });

  test("has fourteen destinations in four groups, and nothing else", () => {
    const sections = navSections({ isAdmin: true });
    expect(sections.filter((s) => s.title).map((s) => s.title)).toEqual(["Traffic", "Security", "Observe", "System"]);
    expect(labels({ isAdmin: true })).toEqual([
      "Overview",
      "Routes",
      "Services",
      "Listeners",
      "Policies",
      "Security",
      "TLS",
      "Logs",
      "Traces",
      "Metrics",
      "Settings",
      "Access",
      "Audit log",
      "Diagnostics",
    ]);
  });

  test("uses plain words, never the API's", () => {
    for (const label of labels({ isAdmin: true })) {
      expect(label).not.toMatch(/EntryPoint|Middleware|Authorit|Option|Hub|Dashboard/);
    }
  });

  test("lists every page once", () => {
    const all = navSections({ isAdmin: true }).flatMap((s) => s.items.map((i) => i.to));
    expect(new Set(all).size).toBe(all.length);
  });
});
