// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, mock, test } from "bun:test";

const calls: unknown[] = [];
let failList = false;

mock.module("../services/client", () => ({
  api: {
    listTraces: async (req: unknown) => {
      calls.push(req);
      if (failList) throw new Error("traces unavailable");
      return {
        $typeName: "gateon.v1.ListTracesResponse",
        traces: [{ $typeName: "gateon.v1.Trace", id: "t1", durationMs: 12, timestamp: "2026-09-26T08:00:00Z" }],
      };
    },
    getTrace: async (req: unknown) => {
      calls.push(req);
      return {
        $typeName: "gateon.v1.GetTraceResponse",
        trace: { $typeName: "gateon.v1.Trace", id: "t1", requestHeaders: { host: "api.example" } },
      };
    },
  },
}));

const { fetchTraces, fetchTrace } = await import("./useTraces");

describe("traces", () => {
  test("the list asks for summaries at the page's limit", async () => {
    calls.length = 0;
    const traces = await fetchTraces(50);
    expect(calls).toEqual([{ limit: 50, summary: true }]);
    expect(traces.map((t) => t.id)).toEqual(["t1"]);
  });

  // The REST call parsed an error body and read its missing `traces` as none,
  // so the page's error state was unreachable.
  test("a failed list rejects, so the page shows its error state", async () => {
    failList = true;
    try {
      await expect(fetchTraces(50)).rejects.toThrow("traces unavailable");
    } finally {
      failList = false;
    }
  });

  test("a trace is loaded by its id and timestamp", async () => {
    calls.length = 0;
    const trace = await fetchTrace("t1", "2026-09-26T08:00:00Z");
    expect(calls).toEqual([{ id: "t1", timestamp: "2026-09-26T08:00:00Z" }]);
    expect(trace?.requestHeaders).toEqual({ host: "api.example" });
  });
});
