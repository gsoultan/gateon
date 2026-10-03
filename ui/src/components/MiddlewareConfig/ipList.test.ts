// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { ipListError, isIPOrCIDR } from "./ipList";

describe("IP filter list entries", () => {
  // Each of these used to save and block nothing.
  test("wildcards, ranges, bad masks and joined entries are named", () => {
    for (const bad of ["127.0.0.*", "127.0.0.0-127.0.0.255", "127.0.0.1/33", "10.0.0/8", "2001:db8::/129", "1.2.3.4 5.6.7.8", "256.0.0.1"]) {
      expect(isIPOrCIDR(bad)).toBe(false);
    }
    expect(ipListError(["10.0.0.1", "127.0.0.*"])).toContain("127.0.0.*");
  });

  test("addresses and CIDRs of both families pass", () => {
    for (const ok of ["127.0.0.1", "192.0.2.0/24", "0.0.0.0/0", "2001:db8::1", "2001:db8:1::/48", "::/0", "::ffff:192.0.2.1"]) {
      expect(isIPOrCIDR(ok)).toBe(true);
    }
    expect(ipListError(["10.0.0.0/8", " "])).toBeNull();
  });
});
