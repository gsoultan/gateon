// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { ATTENTION_CAP, certificateHealth, deriveAttention } from "./attention";
import type { TargetStats } from "../../types/gateon";

const target = (url: string, alive: boolean, circuitState?: string): TargetStats =>
  ({ url, alive, requestCount: 0, errorCount: 0, avgLatencyMs: 0, activeConn: 0, circuitState }) as TargetStats;

describe("deriveAttention", () => {
  test("is empty when everything is fine", () => {
    expect(
      deriveAttention({
        routeStats: { api: [target("http://a", true, "closed")] },
        routeProblems: new Map(),
        certificates: [{ domain: "x", certName: "x", expiryEpoch: 0, daysRemaining: 90 }],
        onboarding: { listeners: 1, services: 1, routes: 1, protected: true },
      }),
    ).toEqual([]);
  });

  test("puts down rows before degraded ones, and setup steps last", () => {
    const items = deriveAttention({
      onboarding: { listeners: 1, services: 1, routes: 1, protected: false },
      certificates: [{ domain: "shop", certName: "shop", expiryEpoch: 0, daysRemaining: 12 }],
      routeStats: { api: [target("http://b", false)] },
    });
    expect(items.map((i) => i.state)).toEqual(["down", "degraded", "unknown"]);
    expect(items[0].title).toBe("Backend unhealthy");
    expect(items[1].title).toBe("Certificate expires in 12 days");
    expect(items[2].action.to).toBe("/policies");
  });

  test("an open circuit is a row even when the target answers health checks", () => {
    const items = deriveAttention({ routeStats: { api: [target("http://c", true, "open")] } });
    expect(items).toHaveLength(1);
    expect(items[0].title).toBe("Backend circuit open");
  });

  test("a resource is a row at 90 percent and not at 89", () => {
    const at = (cpuUsage: number) =>
      deriveAttention({ status: { cpuUsage, memoryUsagePercent: 10 } as never }).length;
    expect(at(89)).toBe(0);
    expect(at(90)).toBe(1);
  });

  test("never exceeds the cap", () => {
    const routeStats = Object.fromEntries(
      Array.from({ length: 30 }, (_, i) => [`r${i}`, [target(`http://t${i}`, false)]]),
    );
    expect(deriveAttention({ routeStats })).toHaveLength(ATTENTION_CAP);
  });
});

describe("certificateHealth", () => {
  test("is unknown only until a snapshot arrives", () => {
    expect(certificateHealth(undefined).state).toBe("unknown");
  });

  test("a snapshot without certificates means none are served, not still waiting", () => {
    // The gateway omits an empty tlsCertificates, so this is what a
    // plain-HTTP gateway's snapshot looks like on the wire.
    expect(certificateHealth({})).toEqual({ state: "off", label: "None", detail: "No certificate is served" });
    expect(certificateHealth({ tlsCertificates: [] }).state).toBe("off");
  });

  test("reports the soonest expiry", () => {
    const cert = (daysRemaining: number) => ({ domain: "x", certName: "x", expiryEpoch: 0, daysRemaining });
    expect(certificateHealth({ tlsCertificates: [cert(90), cert(10)] }).state).toBe("degraded");
    expect(certificateHealth({ tlsCertificates: [cert(0)] }).state).toBe("down");
    expect(certificateHealth({ tlsCertificates: [cert(90)] }).state).toBe("up");
  });
});
