// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { LEGACY_PATHS, legacyRedirect } from "./legacyPaths";
import { navSections } from "./navigation";

const current = new Set(navSections({ isAdmin: true }).flatMap((s) => s.items.map((i) => i.to)));

describe("retired paths", () => {
  test("every old sidebar page redirects somewhere that is in the sidebar", () => {
    for (const [from, target] of Object.entries(LEGACY_PATHS)) {
      expect(current.has(target.to)).toBe(true);
      expect(from).not.toBe(target.to);
    }
  });

  test("EntryPoints becomes Listeners and Middlewares becomes Policies", () => {
    expect(legacyRedirect("/entryPoints")).toEqual({ to: "/listeners" });
    expect(legacyRedirect("/middlewares")).toEqual({ to: "/policies" });
  });

  test("the three TLS pages land on their tab", () => {
    expect(legacyRedirect("/certificates")?.search?.tab).toBe("certificates");
    expect(legacyRedirect("/client-authorities")?.search?.tab).toBe("client-cas");
    expect(legacyRedirect("/tls-options")?.search?.tab).toBe("profiles");
  });

  test("Users and API tokens land on Access", () => {
    expect(legacyRedirect("/users")).toEqual({ to: "/access", search: { tab: "users" } });
    expect(legacyRedirect("/api-tokens")).toEqual({ to: "/access", search: { tab: "tokens" } });
  });

  test("Circuit Breaker, Topology and Path Metrics fold into their new homes", () => {
    expect(legacyRedirect("/circuit-breaker")?.to).toBe("/services");
    expect(legacyRedirect("/topology")).toEqual({ to: "/", search: { tab: "map" } });
    expect(legacyRedirect("/path-metrics")).toEqual({ to: "/metrics-dashboard", search: { tab: "paths" } });
  });

  test("the antivirus alert link still lands on malware scanning", () => {
    expect(legacyRedirect("/clamav")?.to).toBe("/settings");
    expect(legacyRedirect("/clamav")?.search?.tab).toBe("security");
  });

  test("a current path is not redirected", () => {
    for (const to of current) expect(legacyRedirect(to)).toBeUndefined();
  });
});
