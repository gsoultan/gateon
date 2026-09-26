// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, mock, test } from "bun:test";

// The generated client's answers, as protobuf-es v2 builds them: int64 as
// bigint, and every message carrying its $typeName.
mock.module("../services/client", () => ({
  api: {
    listAuditArchives: async () => ({
      $typeName: "gateon.v1.ListAuditArchivesResponse",
      archives: [
        { $typeName: "gateon.v1.AuditArchive", filename: "audit-1.json.br", size: 2048n, createdAt: "2026-09-26T08:00:00Z" },
      ],
    }),
    getAuditArchive: async () => ({
      $typeName: "gateon.v1.GetAuditArchiveResponse",
      logs: [
        {
          $typeName: "gateon.v1.AuditLog",
          id: "1",
          userId: "admin",
          action: "update",
          resource: "route",
          details: "Updated route r1",
          timestamp: "2026-09-26T08:00:00Z",
          ipAddress: "10.0.0.1",
          signature: "sig",
        },
      ],
    }),
  },
}));

const { fetchAuditArchives, getAuditArchive } = await import("./useAuditArchives");

describe("audit archives", () => {
  test("list with a number the page can divide, and the date the page renders", async () => {
    const { archives } = await fetchAuditArchives();
    expect(archives).toEqual([{ filename: "audit-1.json.br", size: 2048, createdAt: "2026-09-26T08:00:00Z" }]);
    expect(archives[0].size / 1024).toBe(2);
  });

  test("open as plain entries, so a download holds no $typeName", async () => {
    const logs = await getAuditArchive("audit-1.json.br");
    expect(logs).toHaveLength(1);
    expect(logs[0].details).toBe("Updated route r1");
    expect(JSON.stringify(logs)).not.toContain("$typeName");
  });
});
