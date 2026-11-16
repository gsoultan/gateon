// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test, mock } from "bun:test";
import type React from "react";
import { MantineProvider } from "@mantine/core";
import { renderToString } from "react-dom/server";
import type { SecurityPosture, WafPosture } from "../../hooks/useSecurityPosture";

// OverviewTab reaches hooks/api, which builds the Connect client from
// window.location at import; there is no window under bun:test.
mock.module("../../services/client", () => ({ api: {} }));
// A Link needs a router in context; the cards under test only need its href.
mock.module("@tanstack/react-router", () => ({
  Link: ({ to, children }: { to: string; children?: React.ReactNode }) => <a href={to}>{children}</a>,
}));

const view = await import("./postureView");
const { SecurityPostureCard } = await import("./OverviewTab");
const { BlindSpotsCard } = await import("./BlindSpotsCard");

const waf = (mode: WafPosture["mode"], total: number, enforcing: number, detecting: number): WafPosture => ({
  enabled: mode !== "off",
  mode,
  routes: { total, enforcing, detecting, unprotected: total - enforcing - detecting, signatureScanning: 0, botManagement: 0, rateLimited: 0 },
  customRulesFromDisk: false,
});

describe("the WAF card (T12)", () => {
  test("an audit-only WAF is detecting, never protecting", () => {
    expect(view.wafStatus(waf("detect", 3, 0, 3)).label).toBe(view.DETECTING_ONLY);
    expect(view.wafStatus(waf("detect", 0, 0, 0)).label).toBe(view.DETECTING_ONLY);
  });

  // ADR 0064: a gateway-wide WAF with every attack family switched off.
  test("a global WAF with every family off is not blocking, even with no route", () => {
    const s = view.wafStatus(waf("no_categories", 0, 0, 0));
    expect(s.label).toBe("Not blocking attacks");
    expect(s.color).toBe("red");
  });

  test("a route whose own WAF is audit-only is not counted as blocking", () => {
    const s = view.wafStatus(waf("enforce", 2, 1, 1));
    expect(s.label).toBe("Blocking on 1 of 2 routes");
    expect(s.detail).toContain("1 detecting only (audit)");
    expect(view.wafDetectsSomewhere(waf("enforce", 2, 1, 1))).toBe(true);
  });

  test("a WAF with every attack category off is not blocking (NEW-13)", () => {
    const w = waf("enforce", 2, 1, 0);
    w.routes.unprotected = 0;
    w.routes.categoriesOff = 1;
    const s = view.wafStatus(w);
    expect(s.label).toBe("Blocking on 1 of 2 routes");
    expect(s.detail).toContain("1 with every attack category off");
    const none = waf("enforce", 1, 0, 0);
    none.routes.unprotected = 0;
    none.routes.categoriesOff = 1;
    expect(view.wafStatus(none).label).toBe("Not blocking attacks");
  });

  test("blocking everywhere says so, and no WAF is disabled", () => {
    expect(view.wafStatus(waf("enforce", 2, 2, 0)).label).toBe("Blocking on all 2 routes");
    expect(view.wafStatus(waf("off", 2, 0, 0)).label).toBe("Disabled");
    expect(view.wafDetectsSomewhere(waf("enforce", 2, 2, 0))).toBe(false);
  });
});

describe("the signature engine card (T4)", () => {
  test("with no file security route it is not running, whatever rules it holds", () => {
    expect(view.signatureStatus({ enabled: false, routes: 0, ruleCount: 0 }).label).toBe("Not running");
  });
  test("it names the rules and the routes it scans", () => {
    expect(view.signatureStatus({ enabled: true, routes: 2, ruleCount: 11 }).label).toBe("11 rules on 2 routes");
  });
});

describe("the reputation card (T31)", () => {
  const rep = (score: number) => ({ fingerprint: "f", score, lastEvent: "", violationCount: 1, history: [] });
  test("says none is lowered instead of a constant 'Good'", () => {
    expect(view.reputationSummary([], 50).value).toBe("None lowered");
  });
  test("counts the lowered clients and gives the lowest score", () => {
    const v = view.reputationSummary([rep(50), rep(0), rep(100)], 50);
    expect(v.value).toBe("2 lowered");
    expect(v.detail).toContain("Lowest score 0/100");
  });
  test("a full page reads as at least that many", () => {
    expect(view.reputationSummary([rep(10), rep(20)], 2).value).toBe("2+ lowered");
  });
});

const posture = (percent: number): SecurityPosture =>
  ({
    score: {
      percent,
      controls: [
        { id: "waf", label: "Web application firewall", weight: 40, state: "partial", credit: 0.5, detail: "0 of 1 routes blocking." },
      ],
    },
  }) as unknown as SecurityPosture;

const renderCard = (p: SecurityPosture | undefined, isLoading = false, error: unknown = null) =>
  renderToString(
    <MantineProvider>
      <SecurityPostureCard posture={p} isLoading={isLoading} error={error} />
    </MantineProvider>,
  );

describe("the posture card (T11)", () => {
  test("shows the server's percentage", () => {
    expect(renderCard(posture(30))).toContain("30%");
  });
  test("shows no number while loading, and says when it is unavailable", () => {
    expect(renderCard(undefined, true)).not.toContain("%</h3>");
    expect(renderCard(undefined, false, new Error("down"))).toContain("Unavailable");
  });
  test("the tooltip states the formula and each control's share", () => {
    expect(view.postureLines(posture(30).score)).toEqual([
      "Web application firewall: 20/40 — 0 of 1 routes blocking.",
    ]);
    expect(view.POSTURE_FORMULA).toContain("traffic and attackers do not move it");
  });
});

describe("what the WAF cannot see", () => {
  const posture = (blindSpots: SecurityPosture["blindSpots"]) => ({ blindSpots }) as SecurityPosture;
  const render = (p: SecurityPosture | undefined, isLoading = false, error: unknown = null) =>
    renderToString(
      <MantineProvider>
        <BlindSpotsCard posture={p} isLoading={isLoading} error={error} />
      </MantineProvider>,
    );

  test("groups are ordered most urgent first and carry their routes", () => {
    const groups = view.blindSpotGroups({
      spots: [
        { kind: "websocket_messages" },
        { kind: "l4_passthrough", route: "r1", name: "ssh" },
        { kind: "waf_detect_only", route: "r2", name: "shop" },
        { kind: "l4_open_to_all", route: "r1", name: "ssh" },
        { kind: "waf_off", route: "r3" },
      ],
    });
    expect(groups.map((g) => g.kind)).toEqual([
      "l4_open_to_all", "waf_off", "waf_detect_only", "l4_passthrough", "websocket_messages",
    ]);
    expect(groups[0].routes).toEqual(["ssh"]);
    // A route with no name is shown by its id, never dropped.
    expect(groups[1].routes).toEqual(["r3"]);
    // The gateway-wide entry names no route; its setting is per route.
    expect(groups[4].routes).toEqual([]);
    expect(groups[4].fix).toContain("WebSocket inspection");
  });

  test("a kind this build does not know is left out, not shown without words", () => {
    const groups = view.blindSpotGroups({ spots: [{ kind: "future_kind" as never, route: "r" }] });
    expect(groups).toEqual([]);
  });

  test("the card names the routes and escapes them", () => {
    const html = render(posture({ spots: [{ kind: "waf_off", route: "r", name: "<img src=x>" }], omitted: 3 }));
    expect(html).toContain("HTTP routes with no WAF");
    expect(html).toContain("&lt;img src=x&gt;");
    expect(html).not.toContain("<img src=x>");
    expect(html).toContain("3 more are not listed here.");
  });

  test("loading, error and an older gateway each say what they are", () => {
    expect(render(undefined, true)).toContain('aria-busy="true"');
    expect(render(undefined, false, new Error("boom"))).toContain("could not be loaded");
    expect(render(undefined, false, new Error("boom"))).not.toContain("boom");
    expect(render({} as SecurityPosture)).toContain("does not report blind spots yet");
  });
});
