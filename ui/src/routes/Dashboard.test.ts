// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import type { RequestDeltaSample } from "../hooks/useGateon";
import type { PathStats, Route, Service } from "../types/gateon";

import {
  buildBandwidthByRouterData,
  buildBandwidthByServiceData,
  buildBandwidthSummaries,
  buildHourlyBandwidthData,
  buildHourlyTrafficData,
  buildRequestTrendData,
  buildTrafficByPathData,
  buildTrafficByPortData,
  buildTrafficByServiceData,
  extractPortLabel,
  filterTrafficSamplesByRange,
  resolveTrafficRangeBounds,
} from "../utils/dashboard";

describe("buildRequestTrendData", () => {
  test("returns empty data for empty history", () => {
    expect(buildRequestTrendData([])).toEqual([]);
  });

  test("maps history values to sequential samples", () => {
    expect(buildRequestTrendData([0, 12, 7])).toEqual([
      { sample: "1", requests: 0 },
      { sample: "2", requests: 12 },
      { sample: "3", requests: 7 },
    ]);
  });
});

describe("extractPortLabel", () => {
  test("extracts explicit ports from host values", () => {
    expect(extractPortLabel("api.example.com:8080")).toBe("8080");
    expect(extractPortLabel("https://edge.example.com:8443")).toBe("8443");
    expect(extractPortLabel("[::1]:9000")).toBe("9000");
  });

  test("returns default when host has no explicit port", () => {
    expect(extractPortLabel("api.example.com")).toBe("default");
    expect(extractPortLabel("  ")).toBe("default");
  });
});

describe("hourly traffic helpers", () => {
  test("aggregates request samples into hourly buckets", () => {
    const hourMs = 60 * 60 * 1000;
    const baseTs = Date.UTC(2026, 3, 4, 10, 15, 0);
    const samples: RequestDeltaSample[] = [
      { ts: baseTs, requests: 5 },
      { ts: baseTs + 20 * 60 * 1000, requests: 7 },
      { ts: baseTs + hourMs + 2 * 60 * 1000, requests: 3 },
    ];

    const hourly = buildHourlyTrafficData(samples);

    expect(hourly).toHaveLength(2);
    expect(hourly[0].requests).toBe(12);
    expect(hourly[1].requests).toBe(3);
    expect(hourly[1].hourStartTs - hourly[0].hourStartTs).toBe(hourMs);
  });

  test("buildHourlyTrafficData pads missing hours when range is provided", () => {
    const hourMs = 60 * 60 * 1000;
    const baseTs = Date.UTC(2026, 3, 4, 10, 0, 0);
    const range = {
      startTs: baseTs,
      endTs: baseTs + 3 * hourMs,
    };
    const samples: RequestDeltaSample[] = [
      { ts: baseTs + hourMs + 5 * 60 * 1000, requests: 5 },
    ];

    const hourly = buildHourlyTrafficData(samples, 60, range);

    expect(hourly).toHaveLength(3);
    expect(hourly[0].requests).toBe(0);
    expect(hourly[0].hourStartTs).toBe(baseTs);
    expect(hourly[1].requests).toBe(5);
    expect(hourly[1].hourStartTs).toBe(baseTs + hourMs);
    expect(hourly[2].requests).toBe(0);
    expect(hourly[2].hourStartTs).toBe(baseTs + 2 * hourMs);
  });

  test("builds preset range bounds from current time", () => {
    const nowTs = Date.UTC(2026, 3, 4, 12, 0, 0);
    const bounds = resolveTrafficRangeBounds("range", "", "last24h", "", "", nowTs);

    expect(bounds).not.toBeNull();
    expect(bounds?.startTs).toBe(nowTs - 24 * 60 * 60 * 1000);
    expect(bounds?.endTs).toBe(nowTs);
  });

  test("filters by specific date bounds", () => {
    const bounds = resolveTrafficRangeBounds(
      "date",
      "2026-04-04",
      "last24h",
      "",
      "",
      Date.UTC(2026, 3, 6, 0, 0, 0),
    );

    expect(bounds).not.toBeNull();
    if (!bounds) {
      return;
    }

    const samples: RequestDeltaSample[] = [
      { ts: bounds.startTs - 1, requests: 1 },
      { ts: bounds.startTs + 1000, requests: 2 },
      { ts: bounds.endTs - 1, requests: 3 },
      { ts: bounds.endTs, requests: 4 },
    ];

    expect(filterTrafficSamplesByRange(samples, bounds)).toEqual([
      { ts: bounds.startTs + 1000, requests: 2 },
      { ts: bounds.endTs - 1, requests: 3 },
    ]);
  });

  test("builds this-month bounds from start of month to now", () => {
    const nowTs = Date.UTC(2026, 5, 16, 12, 30, 0);
    const bounds = resolveTrafficRangeBounds("range", "", "thisMonth", "", "", nowTs);

    expect(bounds).not.toBeNull();
    const expectedStart = new Date(
      new Date(nowTs).getFullYear(),
      new Date(nowTs).getMonth(),
      1,
      0,
      0,
      0,
      0,
    ).getTime();
    expect(bounds?.startTs).toBe(expectedStart);
    expect(bounds?.endTs).toBe(nowTs);
  });

  test("builds this-year bounds from start of year to now", () => {
    const nowTs = Date.UTC(2026, 5, 16, 12, 30, 0);
    const bounds = resolveTrafficRangeBounds("range", "", "thisYear", "", "", nowTs);

    expect(bounds).not.toBeNull();
    const expectedStart = new Date(new Date(nowTs).getFullYear(), 0, 1, 0, 0, 0, 0).getTime();
    expect(bounds?.startTs).toBe(expectedStart);
    expect(bounds?.endTs).toBe(nowTs);
  });

  test("returns null when custom range end is before start", () => {
    expect(
      resolveTrafficRangeBounds(
        "range",
        "",
        "custom",
        "2026-04-05",
        "2026-04-04",
        Date.UTC(2026, 3, 6, 0, 0, 0),
      ),
    ).toBeNull();
  });
});

describe("traffic grouping builders", () => {
  test("groups path stats by port", () => {
    const pathStats: PathStats[] = [
      {
        host: "api.example.com:8080",
        path: "/v1/users",
        requestCount: 30,
        bytesTotal: 3000,
        latencySumSeconds: 3,
        avgLatencySeconds: 0.1,
      },
      {
        host: "edge.example.com:8080",
        path: "/v1/orders",
        requestCount: 20,
        bytesTotal: 2000,
        latencySumSeconds: 4,
        avgLatencySeconds: 0.2,
      },
      {
        host: "gateway.example.com",
        path: "/health",
        requestCount: 10,
        bytesTotal: 1000,
        latencySumSeconds: 1,
        avgLatencySeconds: 0.1,
      },
    ];

    expect(buildTrafficByPortData(pathStats)).toEqual([
      { group: "8080", requests: 50 },
      { group: "default", requests: 10 },
    ]);
  });

  test("aggregates top paths and collapses remaining into Other", () => {
    const pathStats: PathStats[] = [
      { host: "a", path: "/p1", requestCount: 70, bytesTotal: 7000, latencySumSeconds: 1, avgLatencySeconds: 0.1 },
      { host: "a", path: "/p2", requestCount: 60, bytesTotal: 6000, latencySumSeconds: 1, avgLatencySeconds: 0.1 },
      { host: "a", path: "/p3", requestCount: 50, bytesTotal: 5000, latencySumSeconds: 1, avgLatencySeconds: 0.1 },
      { host: "a", path: "/p4", requestCount: 40, bytesTotal: 4000, latencySumSeconds: 1, avgLatencySeconds: 0.1 },
      { host: "a", path: "/p5", requestCount: 30, bytesTotal: 3000, latencySumSeconds: 1, avgLatencySeconds: 0.1 },
      { host: "a", path: "/p6", requestCount: 20, bytesTotal: 2000, latencySumSeconds: 1, avgLatencySeconds: 0.1 },
      { host: "a", path: "/p7", requestCount: 10, bytesTotal: 1000, latencySumSeconds: 1, avgLatencySeconds: 0.1 },
    ];

    expect(buildTrafficByPathData(pathStats)).toEqual([
      { group: "/p1", requests: 70 },
      { group: "/p2", requests: 60 },
      { group: "/p3", requests: 50 },
      { group: "/p4", requests: 40 },
      { group: "/p5", requests: 30 },
      { group: "Other", requests: 30 },
    ]);
  });

  test("maps path traffic to services using route matchers", () => {
    const pathStats: PathStats[] = [
      {
        host: "api.local",
        path: "/v1/users",
        requestCount: 30,
        bytesTotal: 3000,
        latencySumSeconds: 6,
        avgLatencySeconds: 0.2,
      },
      {
        host: "api.local",
        path: "/v1/orders",
        requestCount: 20,
        bytesTotal: 2000,
        latencySumSeconds: 4,
        avgLatencySeconds: 0.2,
      },
      {
        host: "other.local",
        path: "/health",
        requestCount: 10,
        bytesTotal: 1000,
        latencySumSeconds: 1,
        avgLatencySeconds: 0.1,
      },
      {
        host: "other.local",
        path: "/unknown",
        requestCount: 5,
        bytesTotal: 500,
        latencySumSeconds: 1,
        avgLatencySeconds: 0.2,
      },
    ];

    const routes: Route[] = [
      {
        id: "route-users",
        name: "users",
        type: "http",
        entryPoints: ["web"],
        rule: "Host(`api.local`) && PathPrefix(`/v1`)",
        priority: 100,
        middlewares: [],
        serviceId: "svc-users",
      },
      {
        id: "route-health",
        name: "health",
        type: "http",
        entryPoints: ["web"],
        rule: "Path(`/health`)",
        priority: 50,
        middlewares: [],
        serviceId: "svc-health",
      },
    ];

    const services: Service[] = [
      {
        id: "svc-users",
        name: "Users Service",
        weightedTargets: [],
        loadBalancerPolicy: "roundRobin",
        healthCheckPath: "/health",
      },
      {
        id: "svc-health",
        name: "Health Service",
        weightedTargets: [],
        loadBalancerPolicy: "roundRobin",
        healthCheckPath: "/health",
      },
    ];

    expect(buildTrafficByServiceData(pathStats, routes, services)).toEqual([
      { group: "Users Service", requests: 50 },
      { group: "Health Service", requests: 10 },
      { group: "Unmatched", requests: 5 },
    ]);
  });
});

describe("bandwidth helpers", () => {
  test("aggregates total/router/service hourly bandwidth", () => {
    const hourMs = 60 * 60 * 1000;
    const baseTs = Date.UTC(2026, 3, 4, 10, 15, 0);
    const samples = [
      {
        ts: baseTs,
        totalBytes: 1000,
        routerBytes: { users: 700, health: 300 },
        serviceBytes: { users: 800, health: 200 },
      },
      {
        ts: baseTs + 20 * 60 * 1000,
        totalBytes: 500,
        routerBytes: { users: 500, health: 0 },
        serviceBytes: { users: 500, health: 0 },
      },
      {
        ts: baseTs + hourMs,
        totalBytes: 200,
        routerBytes: { users: 0, health: 200 },
        serviceBytes: { users: 0, health: 200 },
      },
    ];

    const hourly = buildHourlyBandwidthData(samples);
    expect(hourly).toHaveLength(2);
    expect(hourly[0]).toMatchObject({
      totalBytes: 1500,
      routerBytes: 1500,
      serviceBytes: 1500,
    });
    expect(hourly[1]).toMatchObject({
      totalBytes: 200,
      routerBytes: 200,
      serviceBytes: 200,
    });
  });

  test("builds max/min/avg summaries from hourly bandwidth", () => {
    const summaries = buildBandwidthSummaries([
      { hourStartTs: 1, hour: "h1", totalBytes: 100, routerBytes: 60, serviceBytes: 80 },
      { hourStartTs: 2, hour: "h2", totalBytes: 300, routerBytes: 90, serviceBytes: 120 },
    ]);

    expect(summaries).toEqual([
      { label: "Total", max: 300, min: 100, avg: 200, color: "indigo" },
      { label: "Router", max: 90, min: 60, avg: 75, color: "orange" },
      { label: "Service", max: 120, min: 80, avg: 100, color: "teal" },
    ]);
  });

  test("maps cumulative bandwidth to router and service groups", () => {
    const pathStats: PathStats[] = [
      {
        host: "api.local",
        path: "/v1/users",
        requestCount: 30,
        bytesTotal: 3000,
        latencySumSeconds: 6,
        avgLatencySeconds: 0.2,
      },
      {
        host: "api.local",
        path: "/v1/orders",
        requestCount: 20,
        bytesTotal: 2000,
        latencySumSeconds: 4,
        avgLatencySeconds: 0.2,
      },
      {
        host: "other.local",
        path: "/unknown",
        requestCount: 5,
        bytesTotal: 500,
        latencySumSeconds: 1,
        avgLatencySeconds: 0.2,
      },
    ];

    const routes: Route[] = [
      {
        id: "route-users",
        name: "users",
        type: "http",
        entryPoints: ["web"],
        rule: "Host(`api.local`) && PathPrefix(`/v1`)",
        priority: 100,
        middlewares: [],
        serviceId: "svc-users",
      },
    ];

    const services: Service[] = [
      {
        id: "svc-users",
        name: "Users Service",
        weightedTargets: [],
        loadBalancerPolicy: "roundRobin",
        healthCheckPath: "/health",
      },
    ];

    expect(buildBandwidthByRouterData(pathStats, routes)).toEqual([
      { group: "users", requests: 5000 },
      { group: "Unmatched", requests: 500 },
    ]);
    expect(buildBandwidthByServiceData(pathStats, routes, services)).toEqual([
      { group: "Users Service", requests: 5000 },
      { group: "Unmatched", requests: 500 },
    ]);
  });
});
