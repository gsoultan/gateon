// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { formatUptime } from "./format";

describe("formatUptime", () => {
  // The live snapshot reports uptime as float seconds, and the status card
  // printed the fraction as it came: "50.395464208s", "3m 5.900000000000006s".
  test("shows whole seconds under an hour", () => {
    expect(formatUptime(50.395464208)).toBe("50s");
    expect(formatUptime(185.9)).toBe("3m 5s");
  });

  test("shows hours and minutes from an hour on", () => {
    expect(formatUptime(3725.2)).toBe("1h 2m");
  });
});
