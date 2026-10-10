// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { create, fromJson, toJson, type JsonValue } from "@bufbuild/protobuf";

import { WafConfigSchema } from "../services/gen/gateon/v1/global_pb";
import type { WafConfig } from "../types/gateon";
import { GLOBAL_WAF_FAMILIES, familiesOff, familySwitchOn, withFamily } from "./wafCategories";

const base: WafConfig = { enabled: true, paranoiaLevel: 1 };

describe("global WAF category switches (ADR 0064)", () => {
  test("an unset switch reads as on, so an upgraded install shows every family running", () => {
    for (const f of GLOBAL_WAF_FAMILIES) {
      expect(familySwitchOn(base, f.key)).toBe(true);
      expect(familySwitchOn({ ...base, categories: null }, f.key)).toBe(true);
    }
    expect(familiesOff(base)).toEqual([]);
  });

  test("switching one off records an explicit false and leaves the others unset", () => {
    const waf = withFamily(base, "sqli", false);
    expect(waf.categories).toEqual({ sqli: false });
    expect(familySwitchOn(waf, "sqli")).toBe(false);
    expect(familySwitchOn(waf, "xss")).toBe(true);
    expect(familiesOff(waf)).toEqual(["SQL Injection"]);
    expect(withFamily(waf, "sqli", true).categories).toEqual({ sqli: true });
  });

  // The card's keys are the proto's JSON names: a misspelt one would be
  // dropped by the gateway (DiscardUnknown) and the switch would do nothing.
  test("every switch the card writes is a field of WafCategories", () => {
    let waf = base;
    for (const f of GLOBAL_WAF_FAMILIES) waf = withFamily(waf, f.key, false);
    const decoded = fromJson(WafConfigSchema, JSON.parse(JSON.stringify(waf)) as JsonValue);
    for (const f of GLOBAL_WAF_FAMILIES) {
      expect(decoded.categories?.[f.key]).toBe(false);
    }
  });

  // The gateway leaves an unset switch out of its JSON (proto3 optional), so a
  // config read and saved unchanged keeps it unset rather than writing false.
  test("a round trip through the gateway's JSON keeps unset switches unset", () => {
    const stored = create(WafConfigSchema, { enabled: true, categories: { lfi: false } });
    const json = toJson(WafConfigSchema, stored, { alwaysEmitImplicit: true }) as unknown as WafConfig;
    const back = fromJson(WafConfigSchema, JSON.parse(JSON.stringify(json)) as JsonValue);
    expect(back.categories?.lfi).toBe(false);
    expect(back.categories?.sqli).toBeUndefined();
  });
});
