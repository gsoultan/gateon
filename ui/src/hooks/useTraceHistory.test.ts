// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, mock, test } from "bun:test";

const calls: unknown[] = [];

mock.module("../services/client", () => ({
  api: {
    queryTraces: async (req: unknown) => {
      calls.push(req);
      return {
        $typeName: "gateon.v1.QueryTracesResponse",
        traces: [{ $typeName: "gateon.v1.Trace", id: "t1", status: "502", timestamp: "2026-09-26T14:05:00Z" }],
        nextCursor: "abc",
        partial: true,
        scannedTo: "2026-09-26T14:05:00Z",
      };
    },
  },
}));

const { fetchTraceHistoryPage, loadedRows, retryUnlessAnswered, HISTORY_PAGE_SIZE } = await import("./useTraceHistory");
const { Code, ConnectError } = await import("@connectrpc/connect");

describe("trace history", () => {
  test("a page asks for the period, the filters and where the last page stopped", async () => {
    calls.length = 0;
    const q = {
      from: "2026-09-26T14:00:00.000Z",
      to: "2026-09-26T15:00:00.000Z",
      oldestFirst: true,
      status: "5xx",
      method: "GET",
      text: "/orders",
    };
    const page = await fetchTraceHistoryPage(q, "cursor-1");
    expect(calls).toEqual([{ ...q, limit: HISTORY_PAGE_SIZE, cursor: "cursor-1" }]);
    expect(page.nextCursor).toBe("abc");
    expect(page.partial).toBe(true);
    expect(page.traces.map((t) => t.id)).toEqual(["t1"]);
  });

  test("rows are counted across the pages loaded", () => {
    const page = (n: number) => ({ traces: Array.from({ length: n }, () => ({}) as never), nextCursor: "", partial: false, scannedTo: "" });
    expect(loadedRows(undefined)).toBe(0);
    expect(loadedRows([page(100), page(100), page(37)])).toBe(237);
  });

  test("an answer is not retried; a failure is, once", () => {
    for (const code of [Code.InvalidArgument, Code.NotFound, Code.ResourceExhausted]) {
      expect(retryUnlessAnswered(0, new ConnectError("answered", code))).toBe(false);
    }
    expect(retryUnlessAnswered(0, new ConnectError("gateway down", Code.Unavailable))).toBe(true);
    expect(retryUnlessAnswered(0, new Error("network"))).toBe(true);
    expect(retryUnlessAnswered(1, new Error("network"))).toBe(false);
  });
});
