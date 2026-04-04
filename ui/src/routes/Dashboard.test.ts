import { describe, expect, test } from "bun:test";
import type { RequestDeltaSample } from "../hooks/useGateon";
import type { PathStats, Route, Service } from "../types/gateon";

import {
  buildHourlyTrafficData,
  buildRequestTrendData,
  buildTrafficByPathData,
  buildTrafficByPortData,
  buildTrafficByServiceData,
  extractPortLabel,
  filterTrafficSamplesByRange,
  resolveTrafficRangeBounds,
} from "./Dashboard";

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
        request_count: 30,
        latency_sum_seconds: 3,
        avg_latency_seconds: 0.1,
      },
      {
        host: "edge.example.com:8080",
        path: "/v1/orders",
        request_count: 20,
        latency_sum_seconds: 4,
        avg_latency_seconds: 0.2,
      },
      {
        host: "gateway.example.com",
        path: "/health",
        request_count: 10,
        latency_sum_seconds: 1,
        avg_latency_seconds: 0.1,
      },
    ];

    expect(buildTrafficByPortData(pathStats)).toEqual([
      { group: "8080", requests: 50 },
      { group: "default", requests: 10 },
    ]);
  });

  test("aggregates top paths and collapses remaining into Other", () => {
    const pathStats: PathStats[] = [
      { host: "a", path: "/p1", request_count: 70, latency_sum_seconds: 1, avg_latency_seconds: 0.1 },
      { host: "a", path: "/p2", request_count: 60, latency_sum_seconds: 1, avg_latency_seconds: 0.1 },
      { host: "a", path: "/p3", request_count: 50, latency_sum_seconds: 1, avg_latency_seconds: 0.1 },
      { host: "a", path: "/p4", request_count: 40, latency_sum_seconds: 1, avg_latency_seconds: 0.1 },
      { host: "a", path: "/p5", request_count: 30, latency_sum_seconds: 1, avg_latency_seconds: 0.1 },
      { host: "a", path: "/p6", request_count: 20, latency_sum_seconds: 1, avg_latency_seconds: 0.1 },
      { host: "a", path: "/p7", request_count: 10, latency_sum_seconds: 1, avg_latency_seconds: 0.1 },
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
        request_count: 30,
        latency_sum_seconds: 6,
        avg_latency_seconds: 0.2,
      },
      {
        host: "api.local",
        path: "/v1/orders",
        request_count: 20,
        latency_sum_seconds: 4,
        avg_latency_seconds: 0.2,
      },
      {
        host: "other.local",
        path: "/health",
        request_count: 10,
        latency_sum_seconds: 1,
        avg_latency_seconds: 0.1,
      },
      {
        host: "other.local",
        path: "/unknown",
        request_count: 5,
        latency_sum_seconds: 1,
        avg_latency_seconds: 0.2,
      },
    ];

    const routes: Route[] = [
      {
        id: "route-users",
        name: "users",
        type: "http",
        entrypoints: ["web"],
        rule: "Host(`api.local`) && PathPrefix(`/v1`)",
        priority: 100,
        middlewares: [],
        service_id: "svc-users",
      },
      {
        id: "route-health",
        name: "health",
        type: "http",
        entrypoints: ["web"],
        rule: "Path(`/health`)",
        priority: 50,
        middlewares: [],
        service_id: "svc-health",
      },
    ];

    const services: Service[] = [
      {
        id: "svc-users",
        name: "Users Service",
        weighted_targets: [],
        load_balancer_policy: "round_robin",
        health_check_path: "/health",
      },
      {
        id: "svc-health",
        name: "Health Service",
        weighted_targets: [],
        load_balancer_policy: "round_robin",
        health_check_path: "/health",
      },
    ];

    expect(buildTrafficByServiceData(pathStats, routes, services)).toEqual([
      { group: "Users Service", requests: 50 },
      { group: "Health Service", requests: 10 },
      { group: "Unmatched", requests: 5 },
    ]);
  });
});
