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

  test("highlights the dashboard on the dashboard only", () => {
    expect(isActivePath("/", "/")).toBe(true);
    expect(isActivePath("/routes", "/")).toBe(false);
  });

  test("lists Users and API Tokens for an administrator only", () => {
    expect(labels({ clamavInstalled: false, isAdmin: true })).toContain("Users");
    expect(labels({ clamavInstalled: false, isAdmin: true })).toContain("API Tokens");
    expect(labels({ clamavInstalled: false, isAdmin: false })).not.toContain("Users");
    expect(labels({ clamavInstalled: false, isAdmin: false })).not.toContain("API Tokens");
  });

  test("lists Antivirus only once ClamAV is installed", () => {
    expect(labels({ clamavInstalled: true, isAdmin: false })).toContain("Antivirus");
    expect(labels({ clamavInstalled: false, isAdmin: false })).not.toContain("Antivirus");
  });

  test("lists every page once", () => {
    const all = navSections({ clamavInstalled: true, isAdmin: true }).flatMap((s) => s.items.map((i) => i.to));
    expect(new Set(all).size).toBe(all.length);
  });
});
