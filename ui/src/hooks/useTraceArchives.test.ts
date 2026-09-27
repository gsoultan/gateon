// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, mock, test } from "bun:test";

// There is no window under bun:test; download URLs are built against the
// page's origin.
(globalThis as { window?: unknown }).window ??= { location: { origin: "https://gw.example" } };

const calls: unknown[] = [];

// The generated client's answers, as protobuf-es v2 builds them: int64 as
// bigint, and every message carrying its $typeName.
mock.module("../services/client", () => ({
  api: {
    listTraceArchives: async (req: unknown) => {
      calls.push(req);
      return {
        $typeName: "gateon.v1.ListTraceArchivesResponse",
        segments: [
          {
            $typeName: "gateon.v1.TraceArchiveSegment",
            name: "traces-2026-09-26T14Z.gw-2.ndjson.zst",
            periodStart: "2026-09-26T14:00:00Z",
            periodEnd: "2026-09-26T15:00:00Z",
            sizeBytes: 3_145_728n,
            traceCount: 40_213n,
            archivedAt: "2026-09-26T15:02:00Z",
            node: "gw-2",
          },
        ],
        nextPageToken: "traces-2026-09-26T14Z.gw-2.ndjson.zst",
        status: {
          $typeName: "gateon.v1.TraceArchiveStatus",
          enabled: true,
          traceStoreActive: true,
          retentionDays: 90,
          maxSizeBytes: 2_147_483_648n,
          segmentCount: 1n,
          totalSizeBytes: 3_145_728n,
          oldestPeriod: "2026-09-26T14:00:00Z",
          newestPeriod: "2026-09-26T14:00:00Z",
          lastArchivedAt: "2026-09-26T15:02:00Z",
          lastError: "",
          lastErrorAt: "",
          node: "gw-1",
          nodes: ["gw-1", "gw-2"],
        },
      };
    },
  },
}));

const { fetchTraceArchivePage, traceArchiveDownloadUrl } = await import("./useTraceArchives");

describe("trace archives", () => {
  test("list with numbers the page can do arithmetic on", async () => {
    const page = await fetchTraceArchivePage("");
    expect(page.segments[0].sizeBytes).toBe(3_145_728);
    expect(page.segments[0].traceCount).toBe(40_213);
    expect(page.status?.maxSizeBytes).toBe(2_147_483_648);
    expect((page.status!.totalSizeBytes / page.status!.maxSizeBytes) * 100).toBeCloseTo(0.146, 2);
    expect(JSON.stringify(page)).not.toContain("$typeName");
  });

  test("say which gateway wrote each hour, and which gateways share the archive", async () => {
    const page = await fetchTraceArchivePage("");
    expect(page.segments[0].node).toBe("gw-2");
    expect(page.status?.node).toBe("gw-1");
    expect(page.status?.nodes).toEqual(["gw-1", "gw-2"]);
  });

  test("page through with the token the page before gave", async () => {
    calls.length = 0;
    await fetchTraceArchivePage("traces-2026-09-26T14Z.gw-2.ndjson.zst");
    expect(calls).toEqual([{ pageSize: 48, pageToken: "traces-2026-09-26T14Z.gw-2.ndjson.zst" }]);
  });

  test("download from the archive route, compressed or as plain NDJSON", () => {
    const name = "traces-2026-09-26T14Z.gw-2.ndjson.zst";
    expect(new URL(traceArchiveDownloadUrl(name, false)).pathname).toBe(`/v1/traces/archives/${name}`);
    const plain = new URL(traceArchiveDownloadUrl(name, true));
    expect(plain.pathname).toBe(`/v1/traces/archives/${name}`);
    expect(plain.searchParams.get("format")).toBe("ndjson");
  });

  test("a name is one path segment, whatever it holds", () => {
    const url = new URL(traceArchiveDownloadUrl("../../gateon.db", false));
    expect(url.pathname).toBe("/v1/traces/archives/..%2F..%2Fgateon.db");
  });
});
