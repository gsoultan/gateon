// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { policyOptions } from "./policyOptions";
import type { Middleware } from "../../types/gateon";

const mws = [
  { id: "ip", name: "Office", type: "ipfilter", config: {} },
  { id: "waf", name: "WAF", type: "waf", config: {} },
] as Middleware[];

describe("policyOptions", () => {
  test("an HTTP route is offered every policy", () => {
    expect(policyOptions(mws, "http", []).map((o) => o.value)).toEqual(["ip", "waf"]);
  });
  test("a TCP route is offered only IP filters", () => {
    expect(policyOptions(mws, "tcp", []).map((o) => o.value)).toEqual(["ip"]);
  });
  test("a UDP route is offered nothing", () => {
    expect(policyOptions(mws, "udp", [])).toEqual([]);
  });
  test("a policy already on a TCP route that does not apply stays visible and is marked", () => {
    expect(policyOptions(mws, "tcp", ["waf"])).toEqual([
      { value: "ip", label: "Office (ipfilter)" },
      { value: "waf", label: "WAF (waf, not applied to TCP routes)" },
    ]);
  });
});
