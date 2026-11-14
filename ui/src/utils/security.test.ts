// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { OTHER_THREAT_TYPES, splitScopedBlock, threatTypeBreakdown } from "./security";

// A fingerprint block is a client build on one network (ADR 0026); the Allow
// dialog names both, so the operator sees exactly whom a release re-admits.
describe("splitScopedBlock", () => {
  test("names the build and the /24 of an IPv4 block", () => {
    expect(splitScopedBlock("t13d1516h2_8daaf6152771_b0da82dd1658|203.0.113")).toEqual({
      build: "t13d1516h2_8daaf6152771_b0da82dd1658",
      network: "203.0.113.0/24",
    });
  });

  test("names the /64 of an IPv6 block as listed", () => {
    expect(splitScopedBlock("_--11--0200_7e33b58890ac|2001:db8:1:2::/64")).toEqual({
      build: "_--11--0200_7e33b58890ac",
      network: "2001:db8:1:2::/64",
    });
  });

  test("is null for an address or anything without a network", () => {
    expect(splitScopedBlock("203.0.113.7")).toBeNull();
    expect(splitScopedBlock("t13d1516h2_8daaf6152771_b0da82dd1658")).toBeNull();
    expect(splitScopedBlock("|203.0.113")).toBeNull();
    expect(splitScopedBlock("t13d1516h2|")).toBeNull();
    expect(splitScopedBlock(undefined)).toBeNull();
  });
});

// The donut's centre read the sum of the five types the server sends, so with
// a sixth type it was smaller than the Threats page's count of every threat.
describe("threatTypeBreakdown", () => {
  test("adds the types outside the top N as one slice, so the slices make the total", () => {
    const { slices, total } = threatTypeBreakdown(
      [
        { label: "waf_blocked", value: 10 },
        { label: "reputation_block", value: 5 },
      ],
      18,
    );
    expect(total).toBe(18);
    expect(slices.map((s) => [s.name, s.value])).toEqual([
      ["WAF_BLOCKED", 10],
      ["REPUTATION_BLOCK", 5],
      [OTHER_THREAT_TYPES, 3],
    ]);
  });

  test("adds no slice when the top types are every threat", () => {
    const { slices, total } = threatTypeBreakdown([{ label: "waf_blocked", value: 4 }], 4);
    expect(total).toBe(4);
    expect(slices).toHaveLength(1);
  });

  test("falls back to the listed types without a total", () => {
    expect(threatTypeBreakdown([{ label: "waf_blocked", value: 4 }], undefined).total).toBe(4);
    expect(threatTypeBreakdown(null, null)).toEqual({ slices: [], total: 0 });
  });
});
