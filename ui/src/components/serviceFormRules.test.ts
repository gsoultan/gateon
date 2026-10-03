// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { HealthCheckType } from "../types/gateon";
import { healthCheckBehaviour, healthCheckProblem, showsWeights, weightsToSave } from "./serviceFormRules";

describe("target weights", () => {
  test("are offered where the balancer reads them: round robin (the default) and weighted", () => {
    expect(showsWeights("roundRobin", "http")).toBe(true);
    expect(showsWeights(undefined, "grpc")).toBe(true);
    expect(showsWeights("weightedRoundRobin", "http")).toBe(true);
    expect(showsWeights("leastConn", "http")).toBe(false);
    expect(showsWeights("roundRobin", "tcp")).toBe(false);
  });

  test("are saved as set where read, and as 1 where the gateway would refuse differing ones", () => {
    const targets = [{ url: "a", weight: 1 }, { url: "b", weight: 6 }];
    expect(weightsToSave(targets, "roundRobin", "http").map((t) => t.weight)).toEqual([1, 6]);
    expect(weightsToSave(targets, "leastConn", "http").map((t) => t.weight)).toEqual([1, 1]);
    expect(weightsToSave(targets, "roundRobin", "udp").map((t) => t.weight)).toEqual([1, 1]);
  });
});

describe("health check", () => {
  test("an explicit HTTP check without a path is refused, as the gateway refuses it", () => {
    expect(healthCheckProblem(HealthCheckType.HEALTH_CHECK_TYPE_HTTP, " ")).toContain("needs a path");
    expect(healthCheckProblem(HealthCheckType.HEALTH_CHECK_TYPE_HTTP, "/healthz")).toBeNull();
    expect(healthCheckProblem(HealthCheckType.HEALTH_CHECK_TYPE_UNSPECIFIED, "")).toBeNull();
  });

  // The form used to say "Leave empty to disable health checks", and with
  // nothing checked a dead backend stayed in rotation reading as healthy.
  test("the default, with no path, says it connects to each target", () => {
    expect(healthCheckBehaviour(HealthCheckType.HEALTH_CHECK_TYPE_UNSPECIFIED, "", "http")).toContain("TCP connection");
    expect(healthCheckBehaviour(HealthCheckType.HEALTH_CHECK_TYPE_UNSPECIFIED, "/hz", "http")).toContain("GET /hz");
    expect(healthCheckBehaviour(HealthCheckType.HEALTH_CHECK_TYPE_TCP, "/hz", "http")).toContain("TCP connection");
    expect(healthCheckBehaviour(HealthCheckType.HEALTH_CHECK_TYPE_UNSPECIFIED, "", "grpc")).toContain("gRPC health");
  });
});
