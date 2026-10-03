// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { routeSwitchOn, type EffectiveWaf } from "../utils/wafEffective";

const enforcingGlobal: EffectiveWaf = {
  mode: "enforcing",
  paranoiaLevel: 1,
  categories: { sqli: true, malware_detection: true, dlp: false },
};

// The route editor showed malware detection OFF on a route WAF that, under the
// global WAF, now runs it (ADR 0044): an untouched switch must read as the
// gateway's merge rule resolves it, and a switch the route set must win.
describe("routeSwitchOn", () => {
  test("an untouched switch inherits what the global WAF runs", () => {
    expect(routeSwitchOn({}, "malware_detection", enforcingGlobal)).toEqual({ on: true, inherited: true });
    expect(routeSwitchOn({}, "dlp", enforcingGlobal)).toEqual({ on: false, inherited: true });
  });

  test("a switch the route set wins over the global WAF", () => {
    expect(routeSwitchOn({ malware_detection: "false" }, "malware_detection", enforcingGlobal)).toEqual({
      on: false,
      inherited: false,
    });
    expect(routeSwitchOn({ sqli: "false" }, "sqli", enforcingGlobal).on).toBe(false);
  });

  test("an empty value is unset, as the gateway reads it", () => {
    expect(routeSwitchOn({ malware_detection: " " }, "malware_detection", enforcingGlobal).inherited).toBe(true);
  });

  test("with the global WAF off, route defaults apply", () => {
    const off: EffectiveWaf = { mode: "off", paranoiaLevel: 0, categories: {} };
    expect(routeSwitchOn({}, "sqli", off)).toEqual({ on: true, inherited: false });
    expect(routeSwitchOn({}, "malware_detection", off)).toEqual({ on: false, inherited: false });
    expect(routeSwitchOn({}, "sqli", undefined).on).toBe(true);
  });

  test("values are parsed as the gateway parses them", () => {
    expect(routeSwitchOn({ sqli: "yes" }, "sqli", undefined).on).toBe(true);
    expect(routeSwitchOn({ malware_detection: "yes" }, "malware_detection", undefined).on).toBe(false);
  });
});
