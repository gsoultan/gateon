// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { archivePath, severalNodes } from "./traceNodes";

describe("trace nodes", () => {
  test("one gateway needs no node column, two do", () => {
    expect(severalNodes([])).toBe(false);
    expect(severalNodes([{ node: "gw-1" }, { node: "gw-1" }])).toBe(false);
    expect(severalNodes([{ node: "gw-1" }, { node: "gw-1" }, { node: "gw-2" }])).toBe(true);
    // A trace from a gateway too old to name itself is still a different one.
    expect(severalNodes([{ node: "gw-1" }, {}])).toBe(true);
  });

  test("an hour's file is under its gateway's directory, then its UTC day's", () => {
    expect(
      archivePath({
        node: "gw-2",
        periodStart: "2026-09-26T14:00:00Z",
        name: "traces-2026-09-26T14Z.gw-2.ndjson.zst",
      }),
    ).toBe("gw-2/2026/09/26/traces-2026-09-26T14Z.gw-2.ndjson.zst");
  });
});
